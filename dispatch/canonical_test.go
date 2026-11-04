package dispatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/cosmos/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func wireBytes(number uint64, data []byte) []byte {
	out := binary.AppendUvarint(nil, number<<3|2)
	out = binary.AppendUvarint(out, uint64(len(data)))
	return append(out, data...)
}

func account(t *testing.T, fill byte) string {
	t.Helper()
	data, err := bech32.ConvertBits(bytes.Repeat([]byte{fill}, 20), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := bech32.Encode("trueopen", data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTakeoverIdentitySeparatesCandidateBindingAndOperation(t *testing.T) {
	var session, task, record, accept [32]byte
	session[0] = 1
	task[0] = 2
	record[0] = 3
	accept[0] = 4
	first, err := TakeoverEntryDigest("testnet", session, 7, task, account(t, 1), 100)
	if err != nil {
		t.Fatal(err)
	}
	replay, _ := TakeoverEntryDigest("testnet", session, 7, task, account(t, 1), 100)
	other, _ := TakeoverEntryDigest("testnet", session, 7, task, account(t, 2), 100)
	rebound, _ := TakeoverEntryDigest("testnet", session, 7, task, account(t, 1), 101)
	dispatch := DispatchEntryDigest("testnet", session, task, record, accept)
	if first != replay || first == other || first == rebound || first == dispatch {
		t.Fatal("operation identity collision")
	}
}

func TestStreamBindingSigningProjectionAndProof(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	a := account(t, 1)
	b := account(t, 2)
	raw := []byte{8, 1}
	raw = append(raw, wireBytes(2, []byte("testnet"))...)
	raw = append(raw, wireBytes(3, []byte(a))...)
	raw = append(raw, wireBytes(4, []byte(b))...)
	raw = append(raw, 40, 9)
	raw = append(raw, wireBytes(6, bytes.Repeat([]byte{5}, 32))...)
	digest, err := SigningDigest("nexus.v1.DispatchStreamBindingV1", raw)
	if err != nil {
		t.Fatal(err)
	}
	ar, _ := AddressBytes(a)
	br, _ := AddressBytes(b)
	want := HashFields("TRUEOPEN_DISPATCH_STREAM_BIND_V1", []byte("testnet"), ar, br, Uint64(9), bytes.Repeat([]byte{5}, 32))
	if digest != want {
		t.Fatal("binding projection differs from the canonical fields")
	}
	sig := SignDigest(key, digest)
	if err := VerifyDigestSignature(key.PubKey().SerializeCompressed(), digest[:], sig); err != nil {
		t.Fatal(err)
	}
	raw = append(raw, wireBytes(7, sig)...)
	again, err := SigningDigest("nexus.v1.DispatchStreamBindingV1", raw)
	if err != nil || again != digest {
		t.Fatal("proof bytes entered their own identity", err)
	}
	sig[0] ^= 1
	if VerifyDigestSignature(key.PubKey().SerializeCompressed(), digest[:], sig) == nil {
		t.Fatal("tampered proof accepted")
	}
}

func TestStrictMaterialRejectsAmbiguousEncodings(t *testing.T) {
	name := "task.v1.BuilderEvidenceV2"
	for _, raw := range [][]byte{{8, 2, 8, 2}, {8, 2, 0xf8, 0x7f, 1}, {8, 0x82, 0}, {8, 2, 18, 0, 26, 0}, {8, 2, 18, 2, 0x78, 1}, {8, 2, 18, 0x80, 0x80, 0x80, 0x80, 0x10}} {
		if err := ValidateMessage(name, raw); !errors.Is(err, ErrDecode) {
			t.Fatalf("ambiguous encoding accepted: %x (%v)", raw, err)
		}
	}
	if err := ValidateMessage(name, []byte{8, 2, 18, 0}); err != nil {
		t.Fatal("valid structural evidence rejected", err)
	}
}

func TestSignedGenerationPenaltyKeepsCanonicalInt32(t *testing.T) {
	// Negative int32 uses a ten-byte sign-extended protobuf varint and projects
	// to the four-byte two's-complement canonical integer, not uint64.
	raw := binary.AppendUvarint([]byte{6 << 3}, ^uint64(0))
	if err := ValidateMessage("task.v1.DecodingParamsV1", raw); err != nil {
		t.Fatal("valid negative penalty rejected", err)
	}
	part, err := canonicalValue(protoTables["task.v1.DecodingParamsV1"][6], value{varint: ^uint64(0)}, 0)
	if err != nil || !bytes.Equal(part, []byte{255, 255, 255, 255}) {
		t.Fatal("signed penalty lost its canonical width", err)
	}
	bad := binary.AppendUvarint([]byte{6 << 3}, uint64(1)<<31)
	if ValidateMessage("task.v1.DecodingParamsV1", bad) == nil {
		t.Fatal("out-of-range positive int32 accepted")
	}
}

func TestFullDrawOrderIsDeterministicAndNeverMutatesPool(t *testing.T) {
	pool := []WeightedMember{{1, 1}, {3, 5}, {7, 2}}
	before := append([]WeightedMember(nil), pool...)
	var random [32]byte
	random[0] = 3
	a, err := DrawOrder("testnet", random, pool, 64)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DrawOrder("testnet", random, pool, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(pool, before) || len(a) != len(pool) {
		t.Fatal("draw is unstable or mutates its inputs")
	}
	seen := map[uint32]bool{}
	for _, slot := range a {
		if seen[slot] {
			t.Fatal("draw repeats a candidate")
		}
		seen[slot] = true
	}
	for _, invalid := range [][]WeightedMember{{{1, 0}}, {{1, 1}, {1, 2}}, {{1, ^uint64(0)}, {2, 1}}} {
		if _, err := DrawOrder("testnet", random, invalid, 64); err == nil {
			t.Fatal("invalid pool accepted")
		}
	}
}
