package dispatch

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedLinkedBuilderEvidence(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name     string `json:"name"`
			Bytes    string `json:"evidence_bytes_hex"`
			Chain    string `json:"chain_id"`
			Operator string `json:"builder_operator"`
			Nonce    uint64 `json:"authorization_nonce"`
			Key      string `json:"public_key_hex"`
			Content  string `json:"content_digest_hex"`
			Evidence string `json:"evidence_id_hex"`
			Fault    string `json:"fault_id_hex"`
		} `json:"builder_evidence_cases"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) != 2 {
		t.Fatal("linked proof branches are missing")
	}
	for _, row := range doc.Cases {
		t.Run(row.Name, func(t *testing.T) {
			got, err := VerifyBuilderEvidenceV2(hexBytes(t, row.Bytes), EvidenceVerifyOptions{
				ChainID: row.Chain,
				LookupCurrentBuilderKey: func(operator string) (ProofKeyBinding, error) {
					if operator != row.Operator {
						t.Fatal("lookup used another operator")
					}
					return ProofKeyBinding{PublicKey: hexBytes(t, row.Key), AuthorizationNonce: row.Nonce, Status: ProofKeyActive}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got.ContentDigest[:]) != row.Content {
				t.Fatal("independent content projection mismatch")
			}
			scope := got.MessageA.Scope.TaskID
			evidence, err := EvidenceID(row.Chain, row.Operator, got.Kind, scope[:], got.ContentDigest)
			if err != nil || hex.EncodeToString(evidence[:]) != row.Evidence {
				t.Fatal("independent evidence ID mismatch", err)
			}
			fault, err := FaultID(row.Chain, row.Operator, got.Kind, scope[:], got.ContentDigest)
			if err != nil || hex.EncodeToString(fault[:]) != row.Fault {
				t.Fatal("independent fault ID mismatch", err)
			}
		})
	}
}
