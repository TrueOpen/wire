package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFixtureManifestAndTamper(t *testing.T) {
	root := t.TempDir()
	fixturePath := filepath.Join(root, "shared", "vector.json")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("{\"value\":1}\n")
	if err := os.WriteFile(fixturePath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	manifest := fixtureManifest{
		Schema: fixtureManifestSchemaV1, Status: "bootstrap-copy",
		SourceRepository: "https://github.com/TrueOpen/node",
		SourceCommit:     "1111111111111111111111111111111111111111",
		Files: []fixtureFile{{
			Path: "shared/vector.json", SourcePath: "x/shared/types/testdata/vector.json",
			Bytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
		}},
	}
	manifestPath := filepath.Join(root, "manifest.json")
	writeFixtureManifest(t, manifestPath, manifest)
	if err := verify(manifestPath); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	if err := os.WriteFile(fixturePath, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify(manifestPath); err == nil {
		t.Fatal("tampered fixture accepted")
	}
}

func TestVerifyFixtureManifestRejectsUnlistedJSON(t *testing.T) {
	root := t.TempDir()
	payload := []byte("{}\n")
	fixturePath := filepath.Join(root, "task", "one.json")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	manifest := fixtureManifest{
		Schema: fixtureManifestSchemaV1, Status: "bootstrap-copy",
		SourceRepository: "https://github.com/TrueOpen/node",
		SourceCommit:     "1111111111111111111111111111111111111111",
		Files: []fixtureFile{{
			Path: "task/one.json", SourcePath: "x/task/types/testdata/one.json",
			Bytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
		}},
	}
	manifestPath := filepath.Join(root, "manifest.json")
	writeFixtureManifest(t, manifestPath, manifest)
	if err := os.WriteFile(filepath.Join(root, "task", "unlisted.json"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify(manifestPath); err == nil {
		t.Fatal("unlisted fixture accepted")
	}
}

// TestVerifyFixtureManifestRejectsCorruptAddressColumn covers the gap the
// SHA-256 check cannot see. A preimage frames address codec bytes, so a fixture
// whose Bech32 column disagrees with its hex sibling still has the digest the
// manifest declares and every downstream digest test stays green. Only a
// decode catches it.
func TestVerifyFixtureManifestRejectsCorruptAddressColumn(t *testing.T) {
	cases := map[string]string{
		"corrupt checksum":  `{"a":[{"type":"address","hex":"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3","bech32":"trueopen1cxphpv8x9ceruv3jt9vueeh88ap5w6tfrx7v3l"}]}` + "\n",
		"hex disagreement":  `{"a":[{"type":"address","hex":"00c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3","bech32":"trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"}]}` + "\n",
		"foreign hrp":       `{"a":[{"type":"address","hex":"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3","bech32":"cosmos1crqu9s7ychrv0jxfet9uenwwelgdr5kn7xpz3t"}]}` + "\n",
		"no hex to compare": `{"a":[{"type":"address","bech32":"trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"}]}` + "\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			manifestPath := writeSingleFixture(t, []byte(body))
			if err := verify(manifestPath); err == nil {
				t.Fatal("fixture with an unverifiable Bech32 column accepted")
			}
		})
	}

	good := `{"a":[{"type":"address","hex":"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3","bech32":"trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"}]}` + "\n"
	if err := verify(writeSingleFixture(t, []byte(good))); err != nil {
		t.Fatalf("fixture with a consistent Bech32 column rejected: %v", err)
	}
}

// writeSingleFixture lays out a one-file fixture tree whose manifest already
// declares the payload's true size and digest, so a rejection can only come
// from a check other than the digest.
func writeSingleFixture(t *testing.T, payload []byte) string {
	t.Helper()
	root := t.TempDir()
	fixturePath := filepath.Join(root, "task", "vector.json")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	manifestPath := filepath.Join(root, "manifest.json")
	writeFixtureManifest(t, manifestPath, fixtureManifest{
		Schema: fixtureManifestSchemaV1, Status: "bootstrap-copy",
		SourceRepository: "https://github.com/TrueOpen/node",
		SourceCommit:     "1111111111111111111111111111111111111111",
		Files: []fixtureFile{{
			Path: "task/vector.json", SourcePath: "x/task/types/testdata/vector.json",
			Bytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
		}},
	})
	return manifestPath
}

func writeFixtureManifest(t *testing.T, path string, manifest fixtureManifest) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}
