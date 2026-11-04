package dispatch

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRosterRequestAndInputAccessBindTheirFullScope(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		field       uint64
		replacement []byte
	}{
		{"nexus.v1.DispatchRosterRequestV1", 6, []byte("different-chain")},
		{"nexus.v1.DispatchRosterRequestV1", 7, []byte(account(t, 2))},
		{"nexus.v1.DispatchInputRequestV1", 6, bytes.Repeat([]byte{0x94}, 32)},
	} {
		var row publishedVector
		for _, candidate := range published(t) {
			if candidate.MessageName == scenario.name {
				row = candidate
				break
			}
		}
		if row.Protobuf == "" {
			t.Fatal("missing authenticated request vector")
		}
		raw := hexBytes(t, row.Protobuf)
		d, err := decode(row.MessageName, raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		old := wireBytes(scenario.field, bytesAt(d, uint32(scenario.field)))
		changed := bytes.Replace(raw, old, wireBytes(scenario.field, scenario.replacement), 1)
		if bytes.Equal(changed, raw) {
			t.Fatal("test did not change its scope field")
		}
		digest, err := SigningDigest(row.MessageName, changed)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyDigestSignature(hexBytes(t, row.PublicKey), digest[:], hexBytes(t, row.Signature)) == nil {
			t.Fatal("request signature replayed across chain, Builder or accepted fact")
		}
	}
}

func TestRetiredDispatchFieldsAndUnknownRevokeReasonFailClosed(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		number uint64
	}{
		{"task.v1.SignedHandraiseRootV1", 8},
		{"task.v1.DispatchTicketV1", 24},
		{"task.v1.DispatchTicketV1", 26},
		{"task.v1.DispatchRecordV1", 21},
	} {
		for _, row := range published(t) {
			if row.MessageName != scenario.name {
				continue
			}
			raw := binary.AppendUvarint(bytes.Clone(hexBytes(t, row.Protobuf)), scenario.number<<3)
			raw = binary.AppendUvarint(raw, 1)
			if _, err := SigningDigest(row.MessageName, raw); err == nil {
				t.Fatal("retired dispatch field was accepted", scenario)
			}
		}
	}
	for _, row := range published(t) {
		if row.MessageName != "nexus.v1.DispatchRevokeV1" {
			continue
		}
		raw := bytes.Replace(hexBytes(t, row.Protobuf), []byte{40, 1}, []byte{40, 2}, 1)
		if _, err := SigningDigest(row.MessageName, raw); err == nil {
			t.Fatal("unknown revoke reason accepted")
		}
	}
}
