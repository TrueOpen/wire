package bus

import (
	"strings"
	"testing"
)

// TestPackedRepeatedScalarIsAccepted covers the encoding that actually travels.
//
// proto3 packs a repeated scalar numeric field by default, so every standard
// encoder writes task.v1.DecodingParamsV1.stop_token_ids as one
// length-delimited block. A decoder that demanded wire type 0 would reject the
// user-signed TaskOrderV2 inside every ORDER_BROADCAST that sets stop tokens,
// while a consumer using generated code accepted it - which is exactly the
// two-implementations-disagree failure the API contract has the wire
// decoder exist to prevent.
func TestPackedRepeatedScalarIsAccepted(t *testing.T) {
	// field 10 << 3 | 2, four payload bytes, elements 1, 2, 300.
	packed := []byte{0x52, 0x04, 0x01, 0x02, 0xac, 0x02}
	message, err := strictDecode(msgDecodingParamsV1, packed)
	if err != nil {
		t.Fatalf("packed repeated uint32 rejected: %v", err)
	}
	if got := message[10]; len(got) != 3 ||
		got[0].varint != 1 || got[1].varint != 2 || got[2].varint != 300 {
		t.Fatalf("packed block decoded to %+v, want 1, 2, 300", got)
	}

	// The unpacked form is legal on the wire too and a parser has to accept it,
	// so a sender that writes one element per tag is not treated as malformed.
	unpacked := []byte{0x50, 0x01, 0x50, 0x02, 0x50, 0xac, 0x02}
	message, err = strictDecode(msgDecodingParamsV1, unpacked)
	if err != nil {
		t.Fatalf("unpacked repeated uint32 rejected: %v", err)
	}
	if got := message[10]; len(got) != 3 || got[2].varint != 300 {
		t.Fatalf("unpacked form decoded to %+v", got)
	}

	// An empty packed block is a legal empty list.
	if _, err := strictDecode(msgDecodingParamsV1, []byte{0x52, 0x00}); err != nil {
		t.Fatalf("empty packed block rejected: %v", err)
	}
}

// TestPackedBlockRejectsBadElements confirms packing does not become a way in.
// The minimal-encoding rule and the exact-consumption rule apply inside the
// block, or a sender could smuggle a value the receiver silently drops.
func TestPackedBlockRejectsBadElements(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  []byte
		want string
	}{
		// 0x81 0x00 is a padded encoding of 1.
		{"non-minimal element", []byte{0x52, 0x02, 0x81, 0x00}, "not minimally encoded"},
		{"truncated element", []byte{0x52, 0x02, 0x01, 0x80}, "truncated"},
		{"block longer than input", []byte{0x52, 0x7f, 0x01}, "remaining"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := strictDecode(msgDecodingParamsV1, testCase.raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

// TestPackingOnlyAppliesToRepeatedScalars pins the other half of the rule. A
// singular varint presented as a length-delimited block, or a bytes field
// presented as a varint, is still rejected: packing widens what a repeated
// scalar may look like and nothing else.
func TestPackingOnlyAppliesToRepeatedScalars(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		field fieldSpec
		wire  uint64
		want  bool
	}{
		{"singular varint as varint", fieldSpec{kind: kindVarint}, wireVarint, true},
		{"singular varint as block", fieldSpec{kind: kindVarint}, wireBytes, false},
		{"repeated varint as varint", fieldSpec{kind: kindVarint, repeated: true}, wireVarint, true},
		{"repeated varint as block", fieldSpec{kind: kindVarint, repeated: true}, wireBytes, true},
		{"bytes as block", fieldSpec{kind: kindBytes}, wireBytes, true},
		{"bytes as varint", fieldSpec{kind: kindBytes}, wireVarint, false},
		{"repeated string as varint", fieldSpec{kind: kindString, repeated: true}, wireVarint, false},
		{"repeated message as varint", fieldSpec{kind: kindMessage, repeated: true}, wireVarint, false},
		{"varint as fixed64", fieldSpec{kind: kindVarint}, wireFixed64, false},
		{"bytes as fixed32", fieldSpec{kind: kindBytes}, wireFixed32, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := acceptsWireType(testCase.field, testCase.wire); got != testCase.want {
				t.Fatalf("acceptsWireType(%+v, %d) = %v, want %v",
					testCase.field, testCase.wire, got, testCase.want)
			}
		})
	}

	// A repeated string is never packable, so a length-delimited entry is one
	// element and not a block to unpack.
	message, err := strictDecode(msgDecodingParamsV1, []byte{0x4a, 0x01, 'a', 0x4a, 0x01, 'b'})
	if err != nil {
		t.Fatalf("repeated string rejected: %v", err)
	}
	if got := message[9]; len(got) != 2 || string(got[0].bytes) != "a" || string(got[1].bytes) != "b" {
		t.Fatalf("repeated string decoded to %+v", got)
	}
}
