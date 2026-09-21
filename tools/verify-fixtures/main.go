package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const fixtureManifestSchemaV1 = "trueopen-wire-fixture-manifest-v1"

// fixtureAddressHRP is the human-readable part of a TrueOpen account address.
const fixtureAddressHRP = "trueopen"

// fixtureOperatorHRP is the validator-operator form of the same 20 bytes. It is
// a separate constant because a Bech32 checksum covers the HRP: the two strings
// share a payload and cannot share a checksum, which is exactly the mistake
// this check exists to catch.
const fixtureOperatorHRP = fixtureAddressHRP + "valoper"

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type fixtureManifest struct {
	Schema           string        `json:"schema"`
	Status           string        `json:"status"`
	SourceRepository string        `json:"source_repository"`
	SourceCommit     string        `json:"source_commit"`
	Notes            []string      `json:"notes,omitempty"`
	Files            []fixtureFile `json:"files"`
}

type fixtureFile struct {
	Path string `json:"path"`
	// Origin is "node" (the default) for a byte copy pinned at SourceCommit, or
	// "wire" for a fixture this repository authors itself. The two carry
	// different provenance: a copy names the upstream path it was taken from, a
	// wire-authored vector names the monorepo rule it pins, because there is no
	// upstream file whose bytes could be compared against it.
	Origin          string `json:"origin,omitempty"`
	SourcePath      string `json:"source_path,omitempty"`
	ContractSection string `json:"contract_section,omitempty"`
	Bytes           int64  `json:"bytes"`
	SHA256          string `json:"sha256"`
}

const (
	originNode = "node"
	originWire = "wire"
)

func (f fixtureFile) origin() string {
	if f.Origin == "" {
		return originNode
	}
	return f.Origin
}

func main() {
	manifestPath := flag.String("manifest", "testdata/v1/manifest.json", "fixture manifest path")
	flag.Parse()
	if err := verify(*manifestPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(manifestPath string) error {
	raw, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer raw.Close()

	var manifest fixtureManifest
	decoder := json.NewDecoder(raw)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode fixture manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}

	root := filepath.Dir(manifestPath)
	declared := make(map[string]struct{}, len(manifest.Files))
	for i, entry := range manifest.Files {
		if err := validateEntry(root, entry, declared); err != nil {
			return fmt.Errorf("fixture %d: %w", i, err)
		}
	}

	actual, err := fixtureJSONPaths(root, filepath.Base(manifestPath))
	if err != nil {
		return err
	}
	declaredPaths := make([]string, 0, len(declared))
	for path := range declared {
		declaredPaths = append(declaredPaths, path)
	}
	sort.Strings(declaredPaths)
	if strings.Join(actual, "\x00") != strings.Join(declaredPaths, "\x00") {
		return fmt.Errorf("manifest coverage mismatch: declared=%v actual=%v", declaredPaths, actual)
	}

	fmt.Printf("verified %d wire fixtures\n", len(manifest.Files))
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing fixture manifest data: %w", err)
	}
	return fmt.Errorf("fixture manifest contains multiple JSON values")
}

func validateManifest(manifest fixtureManifest) error {
	if manifest.Schema != fixtureManifestSchemaV1 {
		return fmt.Errorf("unsupported fixture manifest schema %q", manifest.Schema)
	}
	if manifest.Status != "bootstrap-copy" && manifest.Status != "authoritative" {
		return fmt.Errorf("invalid fixture manifest status %q", manifest.Status)
	}
	if !strings.HasPrefix(manifest.SourceRepository, "https://") {
		return fmt.Errorf("source_repository must be an HTTPS URI")
	}
	if !commitPattern.MatchString(manifest.SourceCommit) {
		return fmt.Errorf("source_commit must be a lowercase 40-byte hex Git object name")
	}
	if len(manifest.Files) == 0 {
		return fmt.Errorf("fixture manifest must contain files")
	}
	// source_commit pins the node copies only. Once the manifest also carries
	// wire-authored vectors, that one commit no longer describes the whole file
	// set, and the manifest has to say so rather than leave a reader to assume
	// every listed fixture came from node.
	for _, entry := range manifest.Files {
		if entry.origin() == originWire && len(manifest.Notes) == 0 {
			return fmt.Errorf("fixture manifest carries wire-authored fixtures, so notes must explain what source_commit still pins")
		}
	}
	return nil
}

func validateEntry(root string, entry fixtureFile, declared map[string]struct{}) error {
	if entry.Path == "" || strings.Contains(entry.Path, `\`) || filepath.IsAbs(entry.Path) {
		return fmt.Errorf("path %q is not a canonical relative slash path", entry.Path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path)))
	if clean != entry.Path || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path %q is not canonical", entry.Path)
	}
	if _, exists := declared[entry.Path]; exists {
		return fmt.Errorf("duplicate path %q", entry.Path)
	}
	declared[entry.Path] = struct{}{}
	if err := validateProvenance(entry); err != nil {
		return err
	}
	if entry.Bytes <= 0 || !hashPattern.MatchString(entry.SHA256) {
		return fmt.Errorf("path %q has invalid size or SHA-256", entry.Path)
	}

	path := filepath.Join(root, filepath.FromSlash(entry.Path))
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", entry.Path, err)
	}
	if !info.Mode().IsRegular() || info.Size() != entry.Bytes {
		return fmt.Errorf("path %q size mismatch: got %d want %d", entry.Path, info.Size(), entry.Bytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != entry.SHA256 {
		return fmt.Errorf("path %q SHA-256 mismatch: got %s want %s", entry.Path, got, entry.SHA256)
	}
	if err := validateAddressColumns(path, entry.Path); err != nil {
		return err
	}
	return validatePublishedVectors(path, entry.Path)
}

// validateAddressColumns re-derives every Bech32 column from its hex sibling.
// A preimage frames the address codec bytes, never the Bech32 presentation
// text, so a vector whose Bech32 column is corrupt still hashes to the expected
// digest and every digest test stays green. The column exists so a reviewer can
// read the vector, which only works if it decodes, so the manifest verifier is
// the one place that has to decode it.
func validateAddressColumns(path, declaredPath string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode %q: %w", declaredPath, err)
	}
	return walkAddressColumns(declaredPath, document)
}

func walkAddressColumns(where string, node any) error {
	switch value := node.(type) {
	case map[string]any:
		if err := checkAddressColumn(where, value); err != nil {
			return err
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := walkAddressColumns(where+"."+key, value[key]); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range value {
			if err := walkAddressColumns(fmt.Sprintf("%s[%d]", where, i), item); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkAddressColumn(where string, object map[string]any) error {
	// A vector that spells the same address in several forms names them
	// <form>_bech32 alongside address_bytes, rather than the bech32/hex pair
	// below. Those went unchecked until an operator address shipped carrying the
	// checksum of a pre-rename HRP, which decodes to nothing and which nothing
	// here noticed.
	if rawHex, ok := object["address_bytes"].(string); ok {
		for key, value := range object {
			if !strings.HasSuffix(key, "bech32") {
				continue
			}
			encoded, ok := value.(string)
			if !ok {
				continue
			}
			if err := checkBech32Against(fmt.Sprintf("%s.%s", where, key), encoded, rawHex); err != nil {
				return err
			}
		}
	}

	encoded, ok := object["bech32"].(string)
	if !ok {
		return nil
	}
	// Without the hex sibling there is nothing to check the text against, and a
	// Bech32 column nobody can check is the state this whole check exists to
	// prevent, so treat the missing sibling as the failure rather than skipping.
	rawHex, ok := object["hex"].(string)
	if !ok {
		return fmt.Errorf("%s: bech32 column %q has no hex sibling to be checked against", where, encoded)
	}
	return checkBech32Against(where, encoded, rawHex)
}

// checkBech32Against decodes one Bech32 string and requires it to carry the
// bytes its hex sibling declares. Decoding validates the checksum, so a string
// whose HRP was rewritten without re-encoding fails here rather than reaching a
// consumer that cannot parse it.
func checkBech32Against(where, encoded, rawHex string) error {
	hrp, decoded, err := decodeBech32(encoded)
	if err != nil {
		return fmt.Errorf("%s: bech32 %q does not decode: %w", where, encoded, err)
	}
	if hrp != fixtureAddressHRP && hrp != fixtureOperatorHRP {
		return fmt.Errorf("%s: bech32 %q carries HRP %q, want %q or %q",
			where, encoded, hrp, fixtureAddressHRP, fixtureOperatorHRP)
	}
	want, err := hex.DecodeString(rawHex)
	if err != nil {
		return fmt.Errorf("%s: hex %q is not hex: %w", where, rawHex, err)
	}
	if !bytes.Equal(decoded, want) {
		return fmt.Errorf("%s: bech32 %q decodes to %s, want the hex sibling %s",
			where, encoded, hex.EncodeToString(decoded), rawHex)
	}
	return nil
}

// validateProvenance keeps the two origins from blurring into each other. The
// point of source_path is that a reviewer can diff the fixture against the node
// tree at source_commit; a wire-authored vector has nothing to diff against, so
// letting it carry a source_path would make an unverifiable claim. It names the
// monorepo section it implements instead, which is what a reviewer can check.
func validateProvenance(entry fixtureFile) error {
	switch entry.origin() {
	case originNode:
		if entry.SourcePath == "" || strings.Contains(entry.SourcePath, `\`) || strings.HasPrefix(entry.SourcePath, "/") ||
			entry.SourcePath == ".." || strings.HasPrefix(entry.SourcePath, "../") {
			return fmt.Errorf("path %q: source_path %q is not canonical", entry.Path, entry.SourcePath)
		}
		if entry.ContractSection != "" {
			return fmt.Errorf("path %q is a node copy, so it is pinned by source_path, not by contract_section", entry.Path)
		}
	case originWire:
		if entry.SourcePath != "" {
			return fmt.Errorf("path %q is wire-authored, so there is no upstream source_path to name", entry.Path)
		}
		if strings.TrimSpace(entry.ContractSection) == "" {
			return fmt.Errorf("path %q is wire-authored and must name the monorepo section it pins", entry.Path)
		}
	default:
		return fmt.Errorf("path %q has unknown origin %q", entry.Path, entry.Origin)
	}
	return nil
}

func fixtureJSONPaths(root, manifestName string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == manifestName {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	sort.Strings(paths)
	return paths, err
}
