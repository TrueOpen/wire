// Package dispatch owns canonical direct-stream signing without generated
// Hub, Task or Nexus imports. Consumers share this implementation.
package dispatch

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"

	"github.com/cosmos/btcutil/bech32"
)

// MaxMessageBytes bounds allocation before decoding signed stream material.
const MaxMessageBytes = 1_048_576

// ErrDecode identifies malformed or out-of-contract protobuf material.
var ErrDecode = errors.New("dispatch: strict decode")

type fieldKind uint8

const (
	kindVarint fieldKind = iota
	kindString
	kindBytes
	kindMessage
)

type fieldSpec struct {
	name     string
	kind     fieldKind
	message  string
	repeated bool
	optional bool
	oneof    int
	bits     int
	boolean  bool
	signed   bool
	address  bool
	hash     bool
	enum     map[uint64]bool
}

type value struct {
	varint uint64
	bytes  []byte
}
type decoded map[uint32][]value
type messageSpec map[uint32]fieldSpec

// FieldFrame returns the existing canonical u64-length-prefixed field frame.
func FieldFrame(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = binary.BigEndian.AppendUint64(out, uint64(len(part)))
		out = append(out, part...)
	}
	return out
}

// HashFields computes one domain-separated canonical commitment.
func HashFields(domain string, fields ...[]byte) [32]byte {
	return sha256.Sum256(FieldFrame(append([][]byte{[]byte(domain)}, fields...)...))
}

// Uint32 and Uint64 encode the protocol's unsigned big-endian integer fields.
func Uint32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func Uint64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// AddressBytes rejects noncanonical account presentations before framing.
func AddressBytes(address string) ([]byte, error) {
	hrp, data, err := bech32.Decode(address, 90)
	if err != nil || hrp != "trueopen" {
		return nil, fmt.Errorf("invalid account address")
	}
	raw, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil || len(raw) != 20 {
		return nil, fmt.Errorf("invalid account address bytes")
	}
	encoded, err := bech32.Encode(hrp, data)
	if err != nil || encoded != address {
		return nil, fmt.Errorf("noncanonical account address")
	}
	return raw, nil
}

func readVarint(data []byte) (uint64, int, error) {
	v, n := binary.Uvarint(data)
	if n <= 0 {
		return 0, 0, fmt.Errorf("%w: malformed varint", ErrDecode)
	}
	if len(binary.AppendUvarint(nil, v)) != n {
		return 0, 0, fmt.Errorf("%w: nonminimal varint", ErrDecode)
	}
	return v, n, nil
}

func decode(name string, raw []byte, depth int) (decoded, error) {
	if len(raw) > messageLimit(name) || depth > 24 {
		return nil, fmt.Errorf("%w: size or nesting limit", ErrDecode)
	}
	spec, ok := protoTables[name]
	if !ok {
		return nil, fmt.Errorf("%w: unregistered message %s", ErrDecode, name)
	}
	out := decoded{}
	selected := map[int]bool{}
	for len(raw) > 0 {
		tag, n, err := readVarint(raw)
		if err != nil {
			return nil, err
		}
		raw = raw[n:]
		if tag>>3 == 0 || tag>>3 > (1<<29)-1 {
			return nil, fmt.Errorf("%w: invalid field number", ErrDecode)
		}
		number := uint32(tag >> 3)
		field, ok := spec[number]
		if !ok {
			return nil, fmt.Errorf("%w: unknown %s field %d", ErrDecode, name, number)
		}
		if !field.repeated && len(out[number]) != 0 {
			return nil, fmt.Errorf("%w: duplicate singular field", ErrDecode)
		}
		if field.oneof > 0 {
			if selected[field.oneof] {
				return nil, fmt.Errorf("%w: duplicate oneof", ErrDecode)
			}
			selected[field.oneof] = true
		}
		var v value
		if field.kind == kindVarint {
			if field.repeated && tag&7 == 2 {
				length, read, err := readVarint(raw)
				if err != nil {
					return nil, err
				}
				raw = raw[read:]
				if length > uint64(len(raw)) || length > MaxMessageBytes {
					return nil, fmt.Errorf("%w: packed length", ErrDecode)
				}
				packed := raw[:int(length)]
				raw = raw[int(length):]
				for len(packed) > 0 {
					scalar, n, e := readVarint(packed)
					if e != nil {
						return nil, e
					}
					packed = packed[n:]
					if e = validateScalar(field, scalar); e != nil {
						return nil, e
					}
					out[number] = append(out[number], value{varint: scalar})
				}
				continue
			}
			if tag&7 != 0 {
				return nil, fmt.Errorf("%w: wrong scalar wire type", ErrDecode)
			}
			v.varint, n, err = readVarint(raw)
			if err != nil {
				return nil, err
			}
			raw = raw[n:]
			if err := validateScalar(field, v.varint); err != nil {
				return nil, err
			}
		} else {
			if tag&7 != 2 {
				return nil, fmt.Errorf("%w: wrong bytes wire type", ErrDecode)
			}
			length, read, err := readVarint(raw)
			if err != nil {
				return nil, err
			}
			raw = raw[read:]
			limit := MaxMessageBytes
			if field.kind == kindMessage {
				limit = messageLimit(field.message)
			}
			if length > uint64(len(raw)) || length > uint64(limit) {
				return nil, fmt.Errorf("%w: bytes length", ErrDecode)
			}
			v.bytes = raw[:int(length)]
			raw = raw[int(length):]
			if field.kind == kindString && !utf8.Valid(v.bytes) {
				return nil, fmt.Errorf("%w: invalid UTF-8", ErrDecode)
			}
			if field.kind == kindMessage {
				if _, err := decode(field.message, v.bytes, depth+1); err != nil {
					return nil, err
				}
			}
		}
		out[number] = append(out[number], v)
	}
	if err := validateStreamShape(name, out); err != nil {
		return nil, err
	}
	if err := validateBuilderSyncShape(name, out); err != nil {
		return nil, err
	}
	return out, nil
}

func messageLimit(name string) int {
	switch name {
	case "task.v1.BuilderEvidenceV2", "task.v1.SignedMessageEquivocationV2":
		return MaxBuilderEvidenceBytesV2
	default:
		return MaxMessageBytes
	}
}

func validateScalar(field fieldSpec, v uint64) error {
	if field.signed && field.bits == 32 {
		if v > math.MaxInt32 && v < uint64(math.MaxUint64-math.MaxInt32) {
			return fmt.Errorf("%w: int32 must be sign-extended", ErrDecode)
		}
	} else if field.bits == 32 && v > math.MaxUint32 {
		return fmt.Errorf("%w: scalar range", ErrDecode)
	}
	if field.boolean && v > 1 {
		return fmt.Errorf("%w: scalar range", ErrDecode)
	}
	if field.enum != nil && !field.enum[v] {
		return fmt.Errorf("%w: unknown enum value", ErrDecode)
	}
	return nil
}

// ValidateMessage strictly checks the entire nested protobuf, never discarding
// unknown fields or collapsing duplicate singular/oneof fields.
func ValidateMessage(name string, raw []byte) error { _, err := decode(name, raw, 0); return err }

// ValidateDescriptorImage compares every pinned message field with the built
// Buf JSON descriptor. It prevents the generated-code-free verifier drifting
// from the schema that consumers actually compile.

func canonicalValue(field fieldSpec, v value, depth int) ([]byte, error) {
	switch field.kind {
	case kindVarint:
		if field.boolean {
			return []byte{byte(v.varint)}, nil
		}
		if field.bits == 32 {
			return Uint32(uint32(v.varint)), nil
		}
		return Uint64(v.varint), nil
	case kindMessage:
		fields, err := canonicalFields(field.message, v.bytes, nil, depth+1)
		if err != nil {
			return nil, err
		}
		return FieldFrame(fields...), nil
	default:
		if field.address {
			return AddressBytes(string(v.bytes))
		}
		if field.hash && len(v.bytes) != 32 {
			return nil, fmt.Errorf("%w: %s requires raw32", ErrDecode, field.name)
		}
		return v.bytes, nil
	}
}

func canonicalFields(name string, raw []byte, excluded map[string]bool, depth int) ([][]byte, error) {
	values, err := decode(name, raw, depth)
	if err != nil {
		return nil, err
	}
	spec := protoTables[name]
	numbers := make([]int, 0, len(spec))
	for n := range spec {
		numbers = append(numbers, int(n))
	}
	sort.Ints(numbers)
	var fields [][]byte
	for _, n := range numbers {
		field := spec[uint32(n)]
		if excluded[field.name] {
			continue
		}
		entries := values[uint32(n)]
		if field.oneof > 0 && len(entries) == 0 {
			continue
		}
		if field.repeated {
			parts := [][]byte{Uint32(uint32(len(entries)))}
			for _, v := range entries {
				part, e := canonicalValue(field, v, depth)
				if e != nil {
					return nil, e
				}
				parts = append(parts, part)
			}
			fields = append(fields, FieldFrame(parts...))
			continue
		}
		if field.optional {
			if len(entries) == 0 {
				fields = append(fields, []byte{0})
				continue
			}
			part, e := canonicalValue(field, entries[0], depth)
			if e != nil {
				return nil, e
			}
			fields = append(fields, append([]byte{1}, FieldFrame(part)...))
			continue
		}
		var v value
		if len(entries) != 0 {
			v = entries[0]
		}
		part, e := canonicalValue(field, v, depth)
		if e != nil {
			return nil, e
		}
		if field.oneof > 0 {
			if field.kind != kindMessage {
				part = FieldFrame(part)
			}
			part = append(Uint32(uint32(n)), part...)
		}
		fields = append(fields, part)
	}
	return fields, nil
}

// SigningPreimage projects a registered signed message in schema field order.
// Signatures are proofs and never enter their own signing projection.
func SigningPreimage(name string, raw []byte) ([]byte, error) {
	domain, ok := signingDomains[name]
	if !ok {
		return nil, fmt.Errorf("unregistered signing message %s", name)
	}
	if name == "nexus.v1.SyncRequest" {
		request, err := decode(name, raw, 0)
		if err != nil {
			return nil, err
		}
		batch, err := decode("nexus.v1.BuilderSyncBatchV1", bytesAt(request, 1), 1)
		if err != nil {
			return nil, err
		}
		sender, err := AddressBytes(string(bytesAt(batch, 3)))
		if err != nil {
			return nil, err
		}
		fields, err := canonicalFields("nexus.v1.BuilderSyncBatchV1", bytesAt(request, 1), nil, 1)
		if err != nil {
			return nil, err
		}
		return FieldFrame([]byte(domain), bytesAt(batch, 2), sender, FieldFrame(fields...)), nil
	}
	excluded := map[string]bool{"service_signature": true, "builder_service_signature": true}
	if name == "nexus.v1.DispatchStreamBindingV1" {
		excluded["schema_version"] = true
	}
	fields, err := canonicalFields(name, raw, excluded, 0)
	if err != nil {
		return nil, err
	}
	return FieldFrame(append([][]byte{[]byte(domain)}, fields...)...), nil
}

// SigningDigest returns the digest signed directly by the current service key.
func SigningDigest(name string, raw []byte) ([32]byte, error) {
	preimage, err := SigningPreimage(name, raw)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// DispatchEntryDigest identifies an accepted dispatch independently of its Tx.
func DispatchEntryDigest(chainID string, taskID, taskHash, recordHash, acceptDigest [32]byte) [32]byte {
	return HashFields("TRUEOPEN_DISPATCH_RECORD_ENTRY_V1", []byte(chainID), Uint32(1), taskID[:], taskHash[:], recordHash[:], acceptDigest[:])
}

// TakeoverEntryDigest isolates candidates and binding generations from dispatch.
func TakeoverEntryDigest(chainID string, sessionID [32]byte, sequence uint64, taskHash [32]byte, candidate string, boundChangeHeight uint64) ([32]byte, error) {
	operator, err := AddressBytes(candidate)
	if err != nil {
		return [32]byte{}, err
	}
	return HashFields("TRUEOPEN_TAKEOVER_ENTRY_V1", []byte(chainID), sessionID[:], Uint64(sequence), taskHash[:], operator, Uint64(boundChangeHeight)), nil
}
