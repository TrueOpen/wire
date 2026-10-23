package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/tools/internal/eip712"
)

func TestSessionKeyAminoSigningVectors(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "session_key_amino_v1.json")
	rows := doc["cases"].([]any)
	if len(rows) != 3 {
		t.Fatal("expected creation, SET and CLEAR")
	}
	for _, raw := range rows {
		row := raw.(map[string]any)
		t.Run(row["name"].(string), func(t *testing.T) {
			canonical := row["canonical_amino_json"].(string)
			var signDoc map[string]any
			if err := json.Unmarshal([]byte(canonical), &signDoc); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(signDoc)
			if err != nil || string(encoded) != canonical {
				t.Fatal("sign doc is not canonical sorted JSON")
			}
			sum := sha256.Sum256([]byte(canonical))
			if hex.EncodeToString(sum[:]) != row["sha256"] {
				t.Fatal("sign doc checksum mismatch")
			}
			messages := signDoc["msgs"].([]any)
			if len(messages) != 1 {
				t.Fatal("one message required")
			}
			msg := messages[0].(map[string]any)
			value := msg["value"].(map[string]any)
			_, hasSet := value["set"]
			clear, hasClear := value["clear"]
			switch row["name"] {
			case "create":
				if value["session_key"] == nil || hasSet || hasClear {
					t.Fatal("creation grant shape")
				}
			case "set":
				if !hasSet || hasClear {
					t.Fatal("SET oneof shape")
				}
			case "clear":
				if hasSet || !hasClear || clear != true {
					t.Fatal("CLEAR is explicit true, never an empty struct")
				}
			}
			delete(signDoc, "msgs")
			signDoc["msg0"] = msg
			messageBytes, err := json.Marshal(signDoc)
			if err != nil {
				t.Fatal(err)
			}
			wantBytes, err := json.Marshal(row["message"])
			if err != nil {
				t.Fatal(err)
			}
			if string(messageBytes) != string(wantBytes) {
				t.Fatal("typed message is not the sign doc projection")
			}
			primary, types, err := eip712.ParseEncodeType(row["encode_type"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(row["encode_type"].(string), "TypeValueClear") {
				t.Fatal("empty structs must not enter the signing graph")
			}
			domain := row["domain"].(map[string]any)
			contract, salt := domain["verifying_contract"].(string), domain["salt"].(string)
			separator, err := (eip712.Domain{Name: domain["name"].(string), Version: domain["version"].(string), ChainID: domain["chain_id"].(string), VerifyingContract: &contract, Salt: &salt}).Separator()
			if err != nil {
				t.Fatal(err)
			}
			hs, err := types.HashStruct(primary, signDoc)
			if err != nil {
				t.Fatal(err)
			}
			digest := eip712.SigningDigest(separator, hs)
			if hex.EncodeToString(hs[:]) != row["hash_struct"] || hex.EncodeToString(separator[:]) != row["domain_separator"] || hex.EncodeToString(digest[:]) != row["signing_digest"] {
				t.Fatal("independent EIP-712 digest mismatch")
			}
			signature, err := hex.DecodeString(row["signature_65"].(string))
			if err != nil {
				t.Fatal(err)
			}
			address, err := eip712.Recover(digest, signature)
			if err != nil || hex.EncodeToString(address[:]) != row["recovered_address"] {
				t.Fatal("wallet signature mismatch")
			}
		})
	}
}
