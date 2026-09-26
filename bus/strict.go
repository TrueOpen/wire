package bus

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// ErrDecode classifies every strict-decode rejection. Callers that need to tell
// "malformed material" from "valid material that fails a check" match on this
// rather than on message text: the two lead to different handling, since a
// malformed submission is never attributable to the signer.
var ErrDecode = errors.New("bus: strict decode")

// MaxCanonicalFieldBytesV1 is the absolute V1 bound for one canonical field or
// H_V1 payload. A transport or domain-specific lower cap still wins; notably,
// BusEnvelopeV1 remains capped by MaxEnvelopeBytes before strict decoding.
const MaxCanonicalFieldBytesV1 = 33_554_432

// MaxPayloadBytes is the existing Bus strict-decoder field bound. Keep this at
// the Bus domain cap; BuilderEvidenceV2 selects its separate 2.1 MB bound via
// strictDecodeWithLimit.
const MaxPayloadBytes = MaxEnvelopeBytes

// protobuf wire types. Groups (3 and 4) are retired and are rejected outright
// rather than skipped: a decoder that skips them cannot claim to have seen every
// field a message carries, which is what unknown-field rejection rests on.
const (
	wireVarint uint64 = iota
	wireFixed64
	wireBytes
	wireStartGroup
	wireEndGroup
	wireFixed32
)

// maxFieldNumber is the largest field number protobuf assigns, 2^29-1. A tag is
// a varint whose upper bits are the field number, and a minimally encoded varint
// can still carry a number far above this bound. Truncating such a tag into a
// uint32 would fold it onto a legitimate field number, so one envelope would
// have several byte encodings and therefore several payload digests - the exact
// property the strict decoder exists to deny.
const maxFieldNumber = 1<<29 - 1

// value is one decoded field. Only the three shapes the projection and the scope
// table read are retained; a fixed32/fixed64 field would need its own accessor,
// and none of the pinned tables declares one.
type value struct {
	varint uint64
	bytes  []byte
}

// decoded is a strictly decoded message: field number to the values that
// arrived. A singular field is rejected before it can appear twice, so len is 1
// for everything except a declared repeated field.
type decoded map[uint32][]value

// strictDecode parses one message against its pinned table.
//
// The rules are the wire API step 1: reject unknown fields, reject a
// duplicate singular field, reject a wrong wire type, and check a length before
// allocating against it. Nothing is skipped and nothing is retained as an
// unknown-field set - "we decoded it and ignored the rest" is exactly the
// posture that lets two implementations disagree about what was signed.
func strictDecode(name string, data []byte) (decoded, error) {
	return strictDecodeWithLimit(name, data, MaxPayloadBytes)
}

func strictDecodeWithLimit(name string, data []byte, maxBytes int) (decoded, error) {
	spec, ok := protoTables[name]
	if !ok {
		return nil, fmt.Errorf("%w: no pinned table for %s", ErrDecode, name)
	}
	if maxBytes <= 0 || maxBytes > MaxCanonicalFieldBytesV1 {
		return nil, fmt.Errorf("%w: invalid strict-decode limit %d", ErrDecode, maxBytes)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, over the %d limit",
			ErrDecode, name, len(data), maxBytes)
	}

	out := make(decoded, len(spec))
	for offset := 0; offset < len(data); {
		tag, read, err := readVarint(data[offset:])
		if err != nil {
			return nil, fmt.Errorf("%w: %s tag: %v", ErrDecode, name, err)
		}
		offset += read

		wireType := tag & 7
		if tag>>3 > maxFieldNumber {
			return nil, fmt.Errorf("%w: %s has field number %d, above the %d protobuf maximum",
				ErrDecode, name, tag>>3, maxFieldNumber)
		}
		number := uint32(tag >> 3)
		if number == 0 {
			return nil, fmt.Errorf("%w: %s has field number 0", ErrDecode, name)
		}
		if wireType == wireStartGroup || wireType == wireEndGroup {
			return nil, fmt.Errorf("%w: %s field %d uses a retired group encoding", ErrDecode, name, number)
		}
		field, known := spec[number]
		if !known {
			return nil, fmt.Errorf("%w: %s has unknown field %d", ErrDecode, name, number)
		}
		if !acceptsWireType(field, wireType) {
			return nil, fmt.Errorf("%w: %s.%s (field %d) has wire type %d, which its declaration does not permit",
				ErrDecode, name, field.name, number, wireType)
		}
		if !field.repeated && len(out[number]) > 0 {
			return nil, fmt.Errorf("%w: %s.%s (field %d) is singular but appears twice",
				ErrDecode, name, field.name, number)
		}

		entries, read, err := readValues(field, wireType, data[offset:], maxBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %s.%s (field %d): %v", ErrDecode, name, field.name, number, err)
		}
		offset += read

		for _, entry := range entries {
			// A message field is decoded now rather than lazily, so an unknown field
			// anywhere in the subtree is rejected by the same pass that accepted the
			// parent. Deferring it would mean the envelope had already been declared
			// well-formed by the time its payload was examined.
			if field.kind == kindMessage {
				if _, err := strictDecodeWithLimit(field.message, entry.bytes, maxBytes); err != nil {
					return nil, err
				}
			}
			if field.kind == kindString && !utf8.Valid(entry.bytes) {
				return nil, fmt.Errorf("%w: %s.%s (field %d) is not valid UTF-8", ErrDecode, name, field.name, number)
			}
		}
		out[number] = append(out[number], entries...)
	}
	return out, nil
}

// acceptsWireType says which wire types a declaration permits.
//
// The subtlety is packing. proto3 packs a repeated scalar numeric field by
// default, so every standard encoder writes `repeated uint32` as one
// length-delimited block - and a decoder that demanded wire type 0 would reject
// the encoding that actually travels. The specification also requires a parser
// to accept the unpacked form of a packable field, so both are permitted here.
//
// That does mean one value has two possible encodings, but it introduces no
// ambiguity about what was signed: payload_digest commits to the exact
// transmitted bytes, so two encodings are two publications rather than two
// readings of one. This is the same reason the digest is defined over an opaque
// byte string instead of a re-marshaled canonical form.
func acceptsWireType(field fieldSpec, wireType uint64) bool {
	if field.kind != kindVarint {
		return wireType == wireBytes
	}
	if field.repeated {
		return wireType == wireVarint || wireType == wireBytes
	}
	return wireType == wireVarint
}

// readValues reads one wire entry, which is one value except for a packed
// repeated scalar block, where it is every element the block contains.
func readValues(field fieldSpec, wireType uint64, data []byte, maxBytes int) ([]value, int, error) {
	if field.kind == kindVarint && wireType == wireVarint {
		raw, read, err := readVarint(data)
		if err != nil {
			return nil, 0, err
		}
		return []value{{varint: raw}}, read, nil
	}

	block, read, err := readLengthDelimited(data, maxBytes)
	if err != nil {
		return nil, 0, err
	}
	if field.kind != kindVarint {
		return []value{{bytes: block}}, read, nil
	}

	// A packed block. Every element is read with the same minimal-encoding rule
	// as a standalone varint, and the block has to be consumed exactly: trailing
	// bytes would be a value the sender wrote and the receiver ignored.
	var out []value
	for offset := 0; offset < len(block); {
		raw, elementRead, err := readVarint(block[offset:])
		if err != nil {
			return nil, 0, fmt.Errorf("packed element at offset %d: %w", offset, err)
		}
		offset += elementRead
		out = append(out, value{varint: raw})
	}
	return out, read, nil
}

func readLengthDelimited(data []byte, maxBytes int) ([]byte, int, error) {
	length, read, err := readVarint(data)
	if err != nil {
		return nil, 0, err
	}
	// The length is checked against the remaining input and the field bound
	// before it is used as a slice index, so a crafted prefix cannot drive an
	// allocation or a panic.
	if length > uint64(maxBytes) {
		return nil, 0, fmt.Errorf("length %d exceeds the %d limit", length, maxBytes)
	}
	if uint64(len(data)-read) < length {
		return nil, 0, fmt.Errorf("length %d exceeds the %d remaining bytes", length, len(data)-read)
	}
	return data[read : read+int(length)], read + int(length), nil
}

func readVarint(data []byte) (uint64, int, error) {
	var out uint64
	for i := 0; i < len(data); i++ {
		if i == 10 {
			return 0, 0, errors.New("varint is longer than 10 bytes")
		}
		b := data[i]
		if i == 9 && b > 1 {
			return 0, 0, errors.New("varint overflows 64 bits")
		}
		out |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			// Protobuf permits a non-minimal varint on the wire, but accepting one
			// here would give two byte strings that decode to one envelope, and
			// therefore two payload digests for one signed projection.
			if i > 0 && b == 0 {
				return 0, 0, errors.New("varint is not minimally encoded")
			}
			return out, i + 1, nil
		}
	}
	return 0, 0, errors.New("varint is truncated")
}

// The accessors below are the only way the projection reads a decoded field.
// Each one states the type the table declares, so a table entry that changes
// shape fails here instead of silently yielding a zero value.

func (d decoded) has(number uint32) bool { return len(d[number]) > 0 }

func (d decoded) uint64At(number uint32) uint64 {
	if !d.has(number) {
		return 0
	}
	return d[number][0].varint
}

func (d decoded) uint32At(name string, number uint32) (uint32, error) {
	raw := d.uint64At(number)
	if raw > math.MaxUint32 {
		return 0, fmt.Errorf("%w: %s field %d is %d, which does not fit in uint32", ErrDecode, name, number, raw)
	}
	return uint32(raw), nil
}

// int32At reads a field the projection treats as a signed 32-bit enum. Protobuf
// encodes a negative enum as a 10-byte varint, so the check is against the
// two's-complement range and not against MaxInt32 alone.
func (d decoded) int32At(name string, number uint32) (int32, error) {
	raw := d.uint64At(number)
	if raw > math.MaxInt32 && raw < 0xffffffff80000000 {
		return 0, fmt.Errorf("%w: %s field %d is %d, which is not an int32 enum value", ErrDecode, name, number, raw)
	}
	return int32(uint32(raw)), nil
}

func (d decoded) stringAt(number uint32) string {
	if !d.has(number) {
		return ""
	}
	return string(d[number][0].bytes)
}

func (d decoded) bytesAt(number uint32) []byte {
	if !d.has(number) {
		return nil
	}
	return d[number][0].bytes
}

// hash32At enforces the raw32 width every Hash32 field in the projection
// declares. The wire API is explicit that a present Hash32 is exactly
// 32 bytes and that a zero-length value is not a way to express absence.
func (d decoded) hash32At(name string, number uint32) ([]byte, error) {
	raw := d.bytesAt(number)
	if len(raw) != 32 {
		return nil, fmt.Errorf("%w: %s field %d is %d bytes, want raw32", ErrDecode, name, number, len(raw))
	}
	return raw, nil
}
