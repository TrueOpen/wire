package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/dispatch"
)

// The relay envelope must transport the already frozen Hub signing vector,
// including its original compact signature, without inventing another digest.
func TestModelSupportRelayPreservesExistingSignedMaterial(t *testing.T) {
	doc := loadIntegratedFixture(t, "hub", "model_support_relay_v1.json")
	hub := loadIntegratedFixture(t, "hub", "hub_domains_v1.json")
	vector := integratedVector(t, hub, "TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1")
	decode := func(value string) []byte {
		t.Helper()
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	field := func(name, key string) string {
		return integratedField(t, vector, name)[key].(string)
	}
	uintField := func(name string) uint64 {
		t.Helper()
		value, err := publishedUint(integratedField(t, vector, name)["value"])
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	confirmation := doc["confirmation"].(map[string]any)
	epochIndex, err := publishedUint(doc["epoch_index"])
	if err != nil {
		t.Fatal(err)
	}
	if doc["chain_id"] != field("chain_id", "utf8") ||
		epochIndex != uintField("epoch_index") ||
		confirmation["operator_address"] != field("operator_address", "bech32") ||
		doc["confirmation_signing_digest"] != "0x"+vector["digest_hex"].(string) {
		t.Fatal("relay diverges from the existing Hub confirmation identity")
	}
	for _, name := range []string{"service_authorization_nonce", "expiry_height"} {
		value, err := publishedUint(confirmation[name])
		if err != nil || value != uintField(name) {
			t.Fatalf("relay changed signed %s", name)
		}
	}
	models := integratedField(t, vector, "models")["fields"].([]any)[1:]
	listed := confirmation["supported_models_hex"].([]any)
	if len(listed) != len(models) {
		t.Fatal("relay changed the signed model count")
	}
	parts := [][]byte{protoBytesField(1, []byte(confirmation["operator_address"].(string)))}
	var repeated []byte
	for i, raw := range models {
		model := raw.(map[string]any)["hex"].(string)
		if listed[i] != model {
			t.Fatal("relay changed the signed model order")
		}
		repeated = append(repeated, protoBytesField(2, decode(model))...)
	}
	parts = append(parts, repeated)
	for i, name := range []string{"service_authorization_nonce", "expiry_height"} {
		parts = append(parts, append(protoVarint(uint64((i+3)<<3)), protoVarint(uintField(name))...))
	}
	signature := decode(confirmation["service_signature_hex"].(string))
	parts = append(parts, protoBytesField(5, signature))
	var equivalent []byte
	for i := len(parts) - 1; i >= 0; i-- {
		equivalent = append(equivalent, parts[i]...)
	}
	original := bytes.Join(parts, nil)
	epoch := append(protoVarint(1<<3), protoVarint(uintField("epoch_index"))...)
	for key, want := range map[string][]byte{
		"confirmation_protobuf_hex":            original,
		"equivalent_confirmation_protobuf_hex": equivalent,
		"request_protobuf_hex":                 append(append([]byte(nil), epoch...), protoBytesField(2, original)...),
		"equivalent_request_protobuf_hex":      append(protoBytesField(2, equivalent), epoch...),
	} {
		if !bytes.Equal(decode(doc[key].(string)), want) {
			t.Fatalf("%s does not transport the original Hub fields", key)
		}
	}
	digest := decode(vector["digest_hex"].(string))
	pub := decode(doc["service_public_key_hex"].(string))
	if err := dispatch.VerifyDigestSignature(pub, digest, signature); err != nil {
		t.Fatal(err)
	}
	for _, raw := range vector["tamper"].([]any) {
		row := raw.(map[string]any)
		if dispatch.VerifyDigestSignature(pub, decode(row["digest_hex"].(string)), signature) == nil {
			t.Fatalf("relay signature did not bind %s", row["name"])
		}
	}
	fingerprint := sha256.Sum256(signature)
	if hex.EncodeToString(fingerprint[:]) != doc["signature_digest_hex"] {
		t.Fatal("relay replay fingerprint is not SHA-256(raw64)")
	}
	responseFields := doc["response"].(map[string]any)
	if responseFields["relay_accepted"] != true || responseFields["idempotent"] != false ||
		responseFields["confirmation_signing_digest"] != doc["confirmation_signing_digest"] {
		t.Fatal("newly accepted response does not acknowledge the signed material")
	}
	response := append([]byte{8, 1}, protoBytesField(2, []byte(doc["confirmation_signing_digest"].(string)))...)
	if !bytes.Equal(response, decode(doc["response_protobuf_hex"].(string))) {
		t.Fatal("response changed the existing signing digest")
	}
}
