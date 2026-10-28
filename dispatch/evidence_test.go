package dispatch

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEvidenceKindsAndDomainIsolation(t *testing.T) {
	scope := bytes.Repeat([]byte{7}, 32)
	operator := account(t, 1)
	content, err := DataUnavailableDigest(DataUnavailableContent{TaskID: scope, VerifyRound: 1, BuilderOperator: operator})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []int32{1, 2, 4} {
		evidence, err := EvidenceID("testnet", operator, kind, scope, content)
		if err != nil {
			t.Fatal(err)
		}
		fault, err := FaultID("testnet", operator, kind, scope, content)
		if err != nil || evidence == fault {
			t.Fatal("evidence/fault domains collapsed", err)
		}
		other, err := EvidenceID("another-chain", operator, kind, scope, content)
		if err != nil || evidence == other {
			t.Fatal("cross-chain identity replay", err)
		}
	}
	for _, kind := range []int32{0, 3, 5, -1} {
		if _, err := EvidenceID("testnet", operator, kind, scope, content); err == nil {
			t.Fatal("inactive evidence kind accepted")
		}
		if _, err := FaultID("testnet", operator, kind, scope, content); err == nil {
			t.Fatal("inactive fault kind accepted")
		}
	}
	for _, tag := range []uint32{0, 1, 4, 6} {
		if _, err := EvidenceKindForTag(tag); err == nil {
			t.Fatal("inactive evidence tag accepted")
		}
	}
	for _, test := range []struct {
		chain, address string
		scope          []byte
	}{
		{"", operator, scope}, {"testnet", "cosmos1invalid", scope}, {"testnet", operator, scope[:31]},
	} {
		if _, err := EvidenceID(test.chain, test.address, 1, test.scope, content); err == nil {
			t.Fatal("malformed identity accepted")
		}
	}
	for violation := int32(0); violation <= 7; violation++ {
		active := violation == 1 || violation == 2
		if IsActiveBuilderProtocolViolation(violation) != active || (ValidateActiveBuilderProtocolViolation(violation) == nil) != active {
			t.Fatal("inactive violation became attributable")
		}
	}
	for _, bad := range []DataUnavailableContent{{TaskID: scope[:31], VerifyRound: 1, BuilderOperator: operator}, {TaskID: scope, VerifyRound: 2, BuilderOperator: operator}, {TaskID: scope, VerifyRound: 1, BuilderOperator: "invalid"}} {
		if _, err := DataUnavailableDigest(bad); err == nil {
			t.Fatal("unattributable availability reference accepted")
		}
	}
}

func TestEvidenceReferenceAndActiveStageBranch(t *testing.T) {
	ref := wireBytes(1, bytes.Repeat([]byte{7}, 32))
	ref = append(ref, 16, 1)
	ref = append(ref, wireBytes(3, []byte(account(t, 1)))...)
	raw := append([]byte{8, 2}, wireBytes(5, ref)...)
	got, err := VerifyBuilderEvidenceV2(raw, EvidenceVerifyOptions{ChainID: "testnet"})
	if err != nil || got.DataUnavailable == nil {
		t.Fatal("valid stable availability reference rejected", err)
	}
	for _, row := range published(t) {
		if row.MessageName != "nexus.v1.OpenVerifyV1" {
			continue
		}
		branch := append([]byte{8, 1}, wireBytes(2, hexBytes(t, row.Protobuf))...)
		branch = append(branch, 24, 2)
		proof := append([]byte{8, 2}, wireBytes(3, branch)...)
		opts := EvidenceVerifyOptions{ChainID: "trueopen-phase1-vector-1", LookupCurrentBuilderKey: func(string) (ProofKeyBinding, error) {
			return ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), AuthorizationNonce: 1, Status: ProofKeyActive}, nil
		}}
		got, err = VerifyBuilderEvidenceV2(proof, opts)
		if err != nil || got.Violation != 2 {
			t.Fatal("active stage proof rejected", err)
		}
		branch[len(branch)-1] = 3
		if _, err = VerifyBuilderEvidenceV2(append([]byte{8, 2}, wireBytes(3, branch)...), opts); err == nil {
			t.Fatal("reserved violation accepted")
		}
		break
	}
}

func TestStrictDecoderBoundsNestedMaterial(t *testing.T) {
	for _, raw := range [][]byte{{0}, {7}, {8, 128}, {0xff, 0xff, 0xff, 0xff, 0x7f}, {10, 1, 255}, {10, 9, 1}} {
		if ValidateMessage("nexus.v1.StreamKeepaliveV1", raw) == nil {
			t.Fatalf("malformed scalar accepted: %x", raw)
		}
	}
	if ValidateMessage("unknown.Type", nil) == nil {
		t.Fatal("unknown message accepted")
	}
	if ValidateMessage("task.v1.BuilderEvidenceV2", make([]byte, MaxBuilderEvidenceBytesV2+1)) == nil {
		t.Fatal("oversized evidence accepted")
	}
	// Packed and unpacked repeated scalar encodings must have identical meaning.
	packed := wireBytes(10, []byte{1, 2})
	unpacked := []byte{80, 1, 80, 2}
	a, err := canonicalFields("task.v1.DecodingParamsV1", packed, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalFields("task.v1.DecodingParamsV1", unpacked, nil, 0)
	if err != nil || !bytes.Equal(FieldFrame(a...), FieldFrame(b...)) {
		t.Fatal("packed scalars changed canonical identity", err)
	}
	tooWide := binary.AppendUvarint(nil, uint64(1)<<32)
	if ValidateMessage("task.v1.DecodingParamsV1", wireBytes(10, tooWide)) == nil {
		t.Fatal("out-of-range packed token ID accepted")
	}
	if ValidateMessage("nexus.v1.BuilderMessageBindingV1", wireBytes(1, []byte{255})) == nil {
		t.Fatal("non-UTF8 chain accepted")
	}
}
