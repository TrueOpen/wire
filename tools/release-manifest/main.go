// Command release-manifest produces and verifies the wire release manifest that
// release/README.md requires of every release, conforming to
// schemas/release-manifest-v1.schema.json.
//
// The manifest is a build artifact, not a committed file. It names the exact
// bytes a release publishes - the descriptor image, the fixture manifest and the
// two registries - each with its size and SHA-256, so a consumer can verify what
// it downloaded without trusting the release page. It cannot be committed for the
// same reason node's registry export carries no source_commit: git_commit has to
// name the commit the release is cut from, and a committed file cannot name the
// commit that contains it.
//
// Two modes:
//
//	release-manifest -write build/release-manifest.json -version v0.1.0 -git-commit <sha> ...
//	release-manifest -manifest build/release-manifest.json
//
// The second mode recomputes every artifact digest from disk and re-checks the
// release scope, so CI verifies the manifest it just produced rather than
// assuming the writer was correct.
package main

import (
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

const (
	releaseManifestSchemaV1  = "trueopen-wire-release-manifest-v1"
	releasePackagesSchemaV1  = "trueopen-wire-release-packages-v1"
	reviewedBreakingSchemaV1 = "trueopen-wire-reviewed-breaking-v1"
)

var (
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	bufPattern     = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	// packagePattern is protobuf package syntax. It is matched here so a typo in
	// release/packages.json fails as a bad package name rather than as a confusing
	// set-comparison mismatch against the proto tree.
	packagePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$`)
	// protoPackageLine extracts the package declaration from a .proto file. The
	// scope check reads the packages out of the sources rather than out of the
	// descriptor image so it works before the image is built.
	protoPackageLine = regexp.MustCompile(`(?m)^package\s+([^;\s]+)\s*;`)
)

// releaseManifest mirrors schemas/release-manifest-v1.schema.json. The JSON key
// names and the required set are the published contract, so
// TestManifestFieldsMatchTheSchema compares this struct against the schema file
// rather than trusting the two to stay aligned by review.
type releaseManifest struct {
	Schema          string        `json:"schema"`
	ProtocolVersion string        `json:"protocol_version"`
	GitCommit       string        `json:"git_commit"`
	BufVersion      string        `json:"buf_version"`
	Descriptor      artifact      `json:"descriptor"`
	FixtureManifest artifact      `json:"fixture_manifest"`
	Registries      []artifact    `json:"registries"`
	ProtoPackages   []string      `json:"proto_packages"`
	Compatibility   compatibility `json:"compatibility"`
}

type artifact struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type compatibility struct {
	Result         string `json:"result"`
	AgainstVersion string `json:"against_version,omitempty"`
	// ReviewedBreaking is present exactly when Result is "reviewed-breaking". It
	// is what stops an approved break from being published as a "pass": the
	// manifest names the declaration by digest, the review that authorized it and
	// how many findings it covers, so a consumer can tell an incompatible release
	// from a compatible one without reading the CI log.
	ReviewedBreaking *reviewedBreaking `json:"reviewed_breaking,omitempty"`
}

type reviewedBreaking struct {
	Declaration  artifact `json:"declaration"`
	Review       string   `json:"review"`
	FindingCount int      `json:"finding_count"`
}

// reviewedBreakingDeclaration reads only the fields the manifest republishes.
// tools/reviewed-breaking owns validating the file; duplicating that here would
// create a second authority on what a valid declaration is.
type reviewedBreakingDeclaration struct {
	Schema          string `json:"schema"`
	ProtocolVersion string `json:"protocol_version"`
	Against         string `json:"against"`
	Review          string `json:"review"`
	Findings        []struct {
		Path    string `json:"path"`
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"findings"`
}

// releasePackages is release/packages.json: the committed release scope.
type releasePackages struct {
	Schema   string            `json:"schema"`
	Notes    []string          `json:"notes"`
	Released []string          `json:"released"`
	Withheld []withheldPackage `json:"withheld"`
}

type withheldPackage struct {
	Package string `json:"package"`
	Reason  string `json:"reason"`
}

// releaseRegistries are the two registry documents every release publishes.
// They are listed here rather than discovered by walking registry/v1 so that
// deleting one is a compile-visible change instead of a quietly shorter release.
var releaseRegistries = []string{
	"registry/v1/domains.json",
	"registry/v1/framing.json",
}

const (
	releaseFixtureManifest = "testdata/v1/manifest.json"
	releasePackagesPath    = "release/packages.json"
	releaseProtoRoot       = "proto"
	// reviewedBreakingPath is the one path a reviewed-breaking declaration may
	// live at. tools/reviewed-breaking defaults to the same path, so the gate that
	// decides and the manifest that records the decision cannot read two files.
	reviewedBreakingPath = "release/reviewed-breaking.json"
)

func reviewedBreakingExists(root string) (bool, error) {
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(reviewedBreakingPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", reviewedBreakingPath)
	}
	return true, nil
}

func main() {
	root := flag.String("root", ".", "repository root")
	manifestPath := flag.String("manifest", "", "verify an existing manifest at this path")
	writePath := flag.String("write", "", "generate a manifest and write it to this path")
	version := flag.String("version", "", "protocol version, e.g. v0.1.0")
	gitCommit := flag.String("git-commit", "", "40-character commit the release is cut from")
	bufVersion := flag.String("buf-version", "", "buf version used to build the descriptor, e.g. v1.71.0")
	descriptor := flag.String("descriptor", "build/wire.binpb", "descriptor image path, relative to root")
	result := flag.String("compatibility", "bootstrap", "buf breaking result: bootstrap, pass or reviewed-breaking")
	against := flag.String("against-version", "", "version the compatibility result was produced against")
	reviewedBreakingPath := flag.String("reviewed-breaking", "", "declaration that authorized a reviewed-breaking result, relative to root")
	flag.Parse()

	if err := run(*root, *manifestPath, *writePath, generateInput{
		version:              *version,
		gitCommit:            *gitCommit,
		bufVersion:           *bufVersion,
		descriptorPath:       *descriptor,
		result:               *result,
		againstVersion:       *against,
		reviewedBreakingPath: *reviewedBreakingPath,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type generateInput struct {
	version              string
	gitCommit            string
	bufVersion           string
	descriptorPath       string
	result               string
	againstVersion       string
	reviewedBreakingPath string
}

func run(root, manifestPath, writePath string, input generateInput) error {
	if (manifestPath == "") == (writePath == "") {
		return fmt.Errorf("exactly one of -manifest or -write is required")
	}

	scope, err := loadReleaseScope(root)
	if err != nil {
		return err
	}

	if writePath != "" {
		manifest, err := generate(root, scope, input)
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(writePath, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s for %s (%d released packages, %d withheld)\n",
			writePath, manifest.ProtocolVersion, len(scope.Released), len(scope.Withheld))
		return nil
	}

	manifest, err := readManifest(manifestPath)
	if err != nil {
		return err
	}
	if err := verify(root, scope, manifest); err != nil {
		return err
	}
	fmt.Printf("verified release manifest %s (%d released packages)\n",
		manifest.ProtocolVersion, len(manifest.ProtoPackages))
	return nil
}

func generate(root string, scope releasePackages, input generateInput) (releaseManifest, error) {
	if !versionPattern.MatchString(input.version) {
		return releaseManifest{}, fmt.Errorf("-version %q is not a semantic version", input.version)
	}
	if !commitPattern.MatchString(input.gitCommit) {
		return releaseManifest{}, fmt.Errorf("-git-commit must be a lowercase 40-byte hex Git object name")
	}
	if !bufPattern.MatchString(input.bufVersion) {
		return releaseManifest{}, fmt.Errorf("-buf-version %q is not vX.Y.Z", input.bufVersion)
	}
	compat, err := buildCompatibility(root, input.result, input.againstVersion, input.reviewedBreakingPath)
	if err != nil {
		return releaseManifest{}, err
	}

	descriptorArtifact, err := describe(root, input.descriptorPath)
	if err != nil {
		return releaseManifest{}, fmt.Errorf("descriptor: %w", err)
	}
	fixtureArtifact, err := describe(root, releaseFixtureManifest)
	if err != nil {
		return releaseManifest{}, fmt.Errorf("fixture manifest: %w", err)
	}
	registries := make([]artifact, 0, len(releaseRegistries))
	for _, path := range releaseRegistries {
		entry, err := describe(root, path)
		if err != nil {
			return releaseManifest{}, fmt.Errorf("registry %s: %w", path, err)
		}
		registries = append(registries, entry)
	}

	return releaseManifest{
		Schema:          releaseManifestSchemaV1,
		ProtocolVersion: input.version,
		GitCommit:       input.gitCommit,
		BufVersion:      input.bufVersion,
		Descriptor:      descriptorArtifact,
		FixtureManifest: fixtureArtifact,
		Registries:      registries,
		ProtoPackages:   append([]string(nil), scope.Released...),
		Compatibility:   compat,
	}, nil
}

// buildCompatibility encodes the rules the schema cannot: "bootstrap" means
// there was no previous release to compare against, so naming one is a
// contradiction; "pass" without one is an unsupported claim; and
// "reviewed-breaking" has to point at the declaration that authorized it, since
// the whole difference between it and "pass" is that evidence.
func buildCompatibility(root, result, against, declarationPath string) (compatibility, error) {
	// Checked here rather than only on verify so a dishonest manifest fails when it
	// is written, not one step later. The presence of a declaration on disk is
	// what decides; a manifest that simply omits the reviewed_breaking block is
	// otherwise self-consistent and would never look at the tree at all.
	declaredOnDisk, err := reviewedBreakingExists(root)
	if err != nil {
		return compatibility{}, err
	}
	if declaredOnDisk && result != "reviewed-breaking" {
		return compatibility{}, fmt.Errorf("%s exists, so this release carries an approved break and its "+
			"result must be reviewed-breaking, not %q", reviewedBreakingPath, result)
	}

	switch result {
	case "bootstrap":
		if against != "" {
			return compatibility{}, fmt.Errorf("bootstrap compatibility has no previous release to compare against, but -against-version is %q", against)
		}
		if declarationPath != "" {
			return compatibility{}, fmt.Errorf("bootstrap compatibility has no baseline to break against, but -reviewed-breaking is %q", declarationPath)
		}
		return compatibility{Result: result}, nil
	case "pass":
		if !versionPattern.MatchString(against) {
			return compatibility{}, fmt.Errorf("a pass compatibility result must name the version it was checked against")
		}
		if declarationPath != "" {
			return compatibility{}, fmt.Errorf("a pass compatibility result reported no findings, so %q authorizes nothing", declarationPath)
		}
		return compatibility{Result: result, AgainstVersion: against}, nil
	case "reviewed-breaking":
		if !versionPattern.MatchString(against) {
			return compatibility{}, fmt.Errorf("a reviewed-breaking result must name the version the break is against")
		}
		if declarationPath == "" {
			return compatibility{}, fmt.Errorf("a reviewed-breaking result must name the declaration that authorized it via -reviewed-breaking")
		}
		entry, declaration, err := describeDeclaration(root, declarationPath)
		if err != nil {
			return compatibility{}, err
		}
		if declaration.Against != against {
			return compatibility{}, fmt.Errorf("%s authorizes a break against %s, but the release is checked against %s",
				declarationPath, declaration.Against, against)
		}
		return compatibility{
			Result:         result,
			AgainstVersion: against,
			ReviewedBreaking: &reviewedBreaking{
				Declaration:  entry,
				Review:       declaration.Review,
				FindingCount: len(declaration.Findings),
			},
		}, nil
	default:
		return compatibility{}, fmt.Errorf("-compatibility must be bootstrap, pass or reviewed-breaking, got %q", result)
	}
}

func describeDeclaration(root, path string) (artifact, reviewedBreakingDeclaration, error) {
	entry, err := describe(root, path)
	if err != nil {
		return artifact{}, reviewedBreakingDeclaration{}, fmt.Errorf("reviewed-breaking declaration: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return artifact{}, reviewedBreakingDeclaration{}, err
	}
	var declaration reviewedBreakingDeclaration
	if err := json.Unmarshal(raw, &declaration); err != nil {
		return artifact{}, reviewedBreakingDeclaration{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if declaration.Schema != reviewedBreakingSchemaV1 {
		return artifact{}, reviewedBreakingDeclaration{}, fmt.Errorf("%s has schema %q, want %q",
			path, declaration.Schema, reviewedBreakingSchemaV1)
	}
	if strings.TrimSpace(declaration.Review) == "" || len(declaration.Findings) == 0 {
		return artifact{}, reviewedBreakingDeclaration{}, fmt.Errorf("%s must name a review and at least one finding", path)
	}
	return entry, declaration, nil
}

// verifyCompatibility re-derives the compatibility block from disk rather than
// re-parsing what the writer claimed. For a reviewed break that matters most: an
// edited declaration, or a manifest naming a declaration digest that no longer
// matches the file, has to fail here, or the digest in the manifest would prove
// nothing about the approval a consumer is being asked to trust.
func verifyCompatibility(root string, got compatibility) error {
	// The presence of a declaration on disk is checked first, and independently of
	// what the manifest claims. Deriving everything from the manifest's own
	// reviewed_breaking block left the one bypass that mattered: a manifest with
	// result "pass" and no block at all was self-consistent and never looked at
	// the tree, so an approved break could be published as compatible.
	declaredOnDisk, err := reviewedBreakingExists(root)
	if err != nil {
		return err
	}
	if declaredOnDisk && got.Result != "reviewed-breaking" {
		return fmt.Errorf("%s exists, so this release carries an approved break and its result must be "+
			"reviewed-breaking, not %q", reviewedBreakingPath, got.Result)
	}

	declarationPath := ""
	if got.ReviewedBreaking != nil {
		declarationPath = got.ReviewedBreaking.Declaration.Path
		// The declaration is pinned to one path for the same reason
		// fixture_manifest is: otherwise a manifest could name a permissive
		// look-alike while the gate that actually decides reads the real file.
		if declarationPath != reviewedBreakingPath {
			return fmt.Errorf("compatibility.reviewed_breaking.declaration must be %s, got %s",
				reviewedBreakingPath, declarationPath)
		}
	}
	want, err := buildCompatibility(root, got.Result, got.AgainstVersion, declarationPath)
	if err != nil {
		return err
	}
	if (want.ReviewedBreaking == nil) != (got.ReviewedBreaking == nil) {
		return fmt.Errorf("compatibility result %q does not agree with the presence of a reviewed_breaking block", got.Result)
	}
	if got.ReviewedBreaking == nil {
		return nil
	}
	if err := verifyArtifact(root, "compatibility.reviewed_breaking.declaration", got.ReviewedBreaking.Declaration); err != nil {
		return err
	}
	if got.ReviewedBreaking.Review != want.ReviewedBreaking.Review {
		return fmt.Errorf("reviewed_breaking.review is %q but %s names %q",
			got.ReviewedBreaking.Review, declarationPath, want.ReviewedBreaking.Review)
	}
	if got.ReviewedBreaking.FindingCount != want.ReviewedBreaking.FindingCount {
		return fmt.Errorf("reviewed_breaking.finding_count is %d but %s declares %d findings",
			got.ReviewedBreaking.FindingCount, declarationPath, want.ReviewedBreaking.FindingCount)
	}
	return nil
}

func verify(root string, scope releasePackages, manifest releaseManifest) error {
	if manifest.Schema != releaseManifestSchemaV1 {
		return fmt.Errorf("unsupported release manifest schema %q", manifest.Schema)
	}
	if !versionPattern.MatchString(manifest.ProtocolVersion) {
		return fmt.Errorf("protocol_version %q is not a semantic version", manifest.ProtocolVersion)
	}
	if !commitPattern.MatchString(manifest.GitCommit) {
		return fmt.Errorf("git_commit must be a lowercase 40-byte hex Git object name")
	}
	if !bufPattern.MatchString(manifest.BufVersion) {
		return fmt.Errorf("buf_version %q is not vX.Y.Z", manifest.BufVersion)
	}
	if err := verifyCompatibility(root, manifest.Compatibility); err != nil {
		return err
	}

	// Every artifact is re-hashed from disk. A manifest that merely parses proves
	// nothing about the bytes a consumer will download.
	if err := verifyArtifact(root, "descriptor", manifest.Descriptor); err != nil {
		return err
	}
	if manifest.FixtureManifest.Path != releaseFixtureManifest {
		return fmt.Errorf("fixture_manifest must be %s, got %s", releaseFixtureManifest, manifest.FixtureManifest.Path)
	}
	if err := verifyArtifact(root, "fixture_manifest", manifest.FixtureManifest); err != nil {
		return err
	}
	declared := make([]string, 0, len(manifest.Registries))
	for i, entry := range manifest.Registries {
		if err := verifyArtifact(root, fmt.Sprintf("registries[%d]", i), entry); err != nil {
			return err
		}
		declared = append(declared, entry.Path)
	}
	want := append([]string(nil), releaseRegistries...)
	sort.Strings(want)
	sort.Strings(declared)
	if strings.Join(want, "\x00") != strings.Join(declared, "\x00") {
		return fmt.Errorf("registries must be exactly %v, got %v", want, declared)
	}

	// proto_packages is the release scope, and the scope is frozen against the
	// proto tree by loadReleaseScope. Comparing here is what stops a manifest from
	// claiming a wider or narrower release than the committed policy allows.
	scopePackages := append([]string(nil), scope.Released...)
	manifestPackages := append([]string(nil), manifest.ProtoPackages...)
	sort.Strings(scopePackages)
	sort.Strings(manifestPackages)
	if strings.Join(scopePackages, "\x00") != strings.Join(manifestPackages, "\x00") {
		return fmt.Errorf("proto_packages %v does not match the released set in %s (%v)",
			manifestPackages, releasePackagesPath, scopePackages)
	}
	return nil
}

func verifyArtifact(root, label string, entry artifact) error {
	if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, `\`) {
		return fmt.Errorf("%s path %q is not a canonical relative slash path", label, entry.Path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path)))
	if clean != entry.Path || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("%s path %q is not canonical", label, entry.Path)
	}
	if !hashPattern.MatchString(entry.SHA256) {
		return fmt.Errorf("%s sha256 is not a lowercase 32-byte hex digest", label)
	}
	got, err := describe(root, entry.Path)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if got.Bytes != entry.Bytes {
		return fmt.Errorf("%s %s size mismatch: got %d want %d", label, entry.Path, got.Bytes, entry.Bytes)
	}
	if got.SHA256 != entry.SHA256 {
		return fmt.Errorf("%s %s SHA-256 mismatch: got %s want %s", label, entry.Path, got.SHA256, entry.SHA256)
	}
	return nil
}

func describe(root, path string) (artifact, error) {
	full := filepath.Join(root, filepath.FromSlash(path))
	info, err := os.Stat(full)
	if err != nil {
		return artifact{}, err
	}
	if !info.Mode().IsRegular() {
		return artifact{}, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() == 0 {
		return artifact{}, fmt.Errorf("%s is empty", path)
	}
	file, err := os.Open(full)
	if err != nil {
		return artifact{}, err
	}
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	if copyErr != nil {
		return artifact{}, copyErr
	}
	if closeErr != nil {
		return artifact{}, closeErr
	}
	return artifact{Path: path, Bytes: info.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

// loadReleaseScope reads release/packages.json and freezes it against the proto
// tree in both directions.
//
// This is the check that makes a narrowed release honest. release/README.md
// requires that the fields intended for the cutover are frozen, and the way to
// satisfy that without waiting for every open upstream decision is to publish a
// smaller scope - but only if the omission is declared. released[] + withheld[]
// == the packages actually present means a new package cannot be published by
// accident and cannot be dropped by accident either.
func loadReleaseScope(root string) (releasePackages, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(releasePackagesPath)))
	if err != nil {
		return releasePackages{}, err
	}
	var scope releasePackages
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scope); err != nil {
		return releasePackages{}, fmt.Errorf("decode %s: %w", releasePackagesPath, err)
	}
	if err := ensureJSONEOF(decoder, releasePackagesPath); err != nil {
		return releasePackages{}, err
	}
	if scope.Schema != releasePackagesSchemaV1 {
		return releasePackages{}, fmt.Errorf("unsupported release packages schema %q", scope.Schema)
	}
	if len(scope.Notes) == 0 {
		return releasePackages{}, fmt.Errorf("%s must explain what the scope means", releasePackagesPath)
	}
	if len(scope.Released) == 0 {
		return releasePackages{}, fmt.Errorf("%s must release at least one package", releasePackagesPath)
	}

	seen := make(map[string]string, len(scope.Released)+len(scope.Withheld))
	for _, name := range scope.Released {
		if !packagePattern.MatchString(name) {
			return releasePackages{}, fmt.Errorf("released package %q is not a protobuf package name", name)
		}
		if where, exists := seen[name]; exists {
			return releasePackages{}, fmt.Errorf("package %q appears twice (%s and released)", name, where)
		}
		seen[name] = "released"
	}
	for _, entry := range scope.Withheld {
		if !packagePattern.MatchString(entry.Package) {
			return releasePackages{}, fmt.Errorf("withheld package %q is not a protobuf package name", entry.Package)
		}
		// A withheld package without a reason is indistinguishable from one somebody
		// forgot to release, which is the whole thing this file exists to prevent.
		if strings.TrimSpace(entry.Reason) == "" {
			return releasePackages{}, fmt.Errorf("withheld package %q must record why it is not frozen yet", entry.Package)
		}
		if where, exists := seen[entry.Package]; exists {
			return releasePackages{}, fmt.Errorf("package %q appears twice (%s and withheld)", entry.Package, where)
		}
		seen[entry.Package] = "withheld"
	}
	if !sort.StringsAreSorted(scope.Released) {
		return releasePackages{}, fmt.Errorf("released packages must be sorted")
	}

	present, err := protoPackages(filepath.Join(root, releaseProtoRoot))
	if err != nil {
		return releasePackages{}, err
	}
	declared := make([]string, 0, len(seen))
	for name := range seen {
		declared = append(declared, name)
	}
	sort.Strings(declared)
	if strings.Join(present, "\x00") != strings.Join(declared, "\x00") {
		return releasePackages{}, fmt.Errorf(
			"%s must account for every proto package exactly once: %s declares %v, %s/ contains %v",
			releasePackagesPath, releasePackagesPath, declared, releaseProtoRoot, present)
	}
	return scope, nil
}

func protoPackages(root string) ([]string, error) {
	found := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".proto" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		match := protoPackageLine.FindSubmatch(raw)
		if match == nil {
			return fmt.Errorf("%s declares no package", path)
		}
		found[string(match[1])] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no proto package found under %s", root)
	}
	packages := make([]string, 0, len(found))
	for name := range found {
		packages = append(packages, name)
	}
	sort.Strings(packages)
	return packages, nil
}

func readManifest(path string) (releaseManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return releaseManifest{}, err
	}
	var manifest releaseManifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return releaseManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder, path); err != nil {
		return releaseManifest{}, err
	}
	return manifest, nil
}

func ensureJSONEOF(decoder *json.Decoder, path string) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing data in %s: %w", path, err)
	}
	return fmt.Errorf("%s contains multiple JSON values", path)
}
