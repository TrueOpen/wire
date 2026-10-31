package dispatch

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestActiveDispatchIdentityVariantVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Name   string `json:"name"`
			Digest string `json:"digest_hex"`
			Fields []struct {
				UTF8   string `json:"utf8"`
				Hex    string `json:"hex"`
				Bech32 string `json:"bech32"`
				Value  uint64 `json:"value"`
			} `json:"fields"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile("../testdata/v1/task/dispatch_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	seen := 0
	decode := func(value string) []byte {
		raw, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, vector := range fixture.Vectors {
		var digest [32]byte
		switch vector.Name {
		case "builder_content_tag_5":
			digest, err = DataUnavailableDigest(DataUnavailableContent{TaskID: decode(vector.Fields[2].Hex), VerifyRound: uint32(vector.Fields[3].Value), BuilderOperator: vector.Fields[4].Bech32})
		case "weighted_draw_worker_dispatch_v1":
			randomness := decode(vector.Fields[2].Hex)
			if len(randomness) != 32 {
				t.Fatal("randomness must be raw32")
			}
			digest = dispatchDrawDigest(vector.Fields[0].UTF8, [32]byte(randomness), vector.Fields[3].Value)
		case "builder_evidence_id_tag_5", "builder_fault_id_tag_5":
			content := decode(vector.Fields[4].Hex)
			if len(content) != 32 {
				t.Fatal("content digest must be raw32")
			}
			if vector.Name == "builder_evidence_id_tag_5" {
				digest, err = EvidenceID(vector.Fields[0].UTF8, vector.Fields[1].Bech32, int32(vector.Fields[2].Value), decode(vector.Fields[3].Hex), [32]byte(content))
			} else {
				digest, err = FaultID(vector.Fields[0].UTF8, vector.Fields[1].Bech32, int32(vector.Fields[2].Value), decode(vector.Fields[3].Hex), [32]byte(content))
			}
		default:
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(digest[:]); got != vector.Digest {
			t.Fatalf("%s: got %s, want %s", vector.Name, got, vector.Digest)
		}
		seen++
	}
	if seen != 4 {
		t.Fatalf("checked %d active identity variants, want 4", seen)
	}
}
