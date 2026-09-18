package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePublishedVectorsRejectsEncodedLegacyBrand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	legacy := hex.EncodeToString([]byte{0x53, 0x49, 0x4e, 0x47, 0x41, 0x5f, 0x54, 0x45, 0x53, 0x54})
	body := fmt.Sprintf(`{"value_hex":%q}`, legacy)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedVectors(path, "fixture.json"); err == nil || !strings.Contains(err.Error(), "legacy brand") {
		t.Fatalf("expected legacy-brand rejection, got %v", err)
	}
}

func TestValidatePublishedVectorsChecksTypedPreimageAndDigest(t *testing.T) {
	domain := "TRUEOPEN_TEST_V1"
	preimage := encodeFrame([]byte(domain), publishedU32(7), []byte("value"))
	digest := sha256.Sum256(preimage)
	body := fmt.Sprintf(`{
  "vectors": [{
    "domain": %q,
    "framing": "H_FIELDS_V1",
    "fields": [
      {"name":"count","type":"uint32","value":7},
      {"name":"label","type":"string","utf8":"value"}
    ],
    "preimage_hex": %q,
    "digest_hex": %q
  }]
}`, domain, hex.EncodeToString(preimage), hex.EncodeToString(digest[:]))
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedVectors(path, "fixture.json"); err != nil {
		t.Fatalf("valid vector rejected: %v", err)
	}

	bad := strings.Replace(body, hex.EncodeToString(digest[:]), strings.Repeat("0", 64), 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedVectors(path, "fixture.json"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected digest rejection, got %v", err)
	}
}
