package dispatch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedValueEvidenceProjectionAndBounds(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "value_evidence_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name     string `json:"name"`
			Protobuf string `json:"protobuf_hex"`
			Chain    string `json:"chain_id"`
			Digest   string `json:"digest_hex"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) != 2 {
		t.Fatal("both active evidence branches need vectors")
	}
	for _, row := range doc.Vectors {
		t.Run(row.Name, func(t *testing.T) {
			raw := hexBytes(t, row.Protobuf)
			got, err := ValueEvidenceDigest(row.Chain, raw, MaxMessageBytes, 8)
			if err != nil || hex.EncodeToString(got[:]) != row.Digest {
				t.Fatal("independent value proof digest mismatch", err)
			}
			other, err := ValueEvidenceDigest("other-chain", raw, MaxMessageBytes, 8)
			if err != nil || got == other {
				t.Fatal("value proof crosses chain identity", err)
			}
			for _, bounds := range []struct {
				size      uint64
				positions uint32
			}{{uint64(len(raw) - 1), 8}, {MaxMessageBytes, 0}} {
				if _, err := DecodeValueEvidence(raw, bounds.size, bounds.positions); err == nil {
					t.Fatal("evidence cap bypassed")
				}
			}
			d, err := decode("task.v1.VerifierValueEvidenceV1", raw, 0)
			if err != nil {
				t.Fatal(err)
			}
			position := d[7][0].bytes
			duplicate := append(append([]byte(nil), raw...), wireBytes(7, position)...)
			if _, err = DecodeValueEvidence(duplicate, MaxMessageBytes, 8); err == nil {
				t.Fatal("duplicate positions accepted")
			}
			withPath := append(append([]byte(nil), position...), wireBytes(3, bytes.Repeat([]byte{9}, 32))...)
			changed := bytes.Replace(raw, wireBytes(7, position), wireBytes(7, withPath), 1)
			proofOnly, err := ValueEvidenceDigest(row.Chain, changed, MaxMessageBytes, 8)
			if err != nil || proofOnly != got {
				t.Fatal("proof path changed semantic evidence identity", err)
			}
			badPath := append(append([]byte(nil), position...), wireBytes(3, []byte{9})...)
			if _, err = DecodeValueEvidence(bytes.Replace(raw, wireBytes(7, position), wireBytes(7, badPath), 1), MaxMessageBytes, 8); err == nil {
				t.Fatal("short proof node accepted")
			}
			unknown := append(append([]byte(nil), raw...), 0xf8, 0x3e, 1)
			if _, err = DecodeValueEvidence(unknown, MaxMessageBytes, 8); err == nil {
				t.Fatal("unknown evidence field accepted")
			}
			if _, err = ValueEvidenceDigest("", raw, MaxMessageBytes, 8); err == nil {
				t.Fatal("missing chain accepted")
			}
		})
	}
}
