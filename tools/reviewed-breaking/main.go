// Command reviewed-breaking turns a buf breaking failure into a decision.
//
// The problem it solves: this repository's compatibility gate has exactly two
// outcomes, pass or fail, and a reviewed breaking release is neither. Disabling
// the gate for the release would also disable it for every unintended break in
// the same commit, and a wildcard `breaking.ignore` in buf.yaml would keep doing
// so for every release after it. Both trade one honest failure for a permanent
// blind spot.
//
// So the gate stays on and its findings are checked against a committed
// declaration instead. release/reviewed-breaking.json names the baseline, the
// review that authorized the break, and the exact set of findings the release is
// allowed to produce. A finding that is not declared fails the build; a declared
// finding that no longer appears also fails it, because a declaration that has
// drifted from the code is no longer evidence of anything.
//
// Two modes:
//
//	# CI: buf writes its findings, this decides.
//	buf breaking --against '.git#tag=v0.1.1' --error-format=json > build/breaking.json || true
//	reviewed-breaking -findings build/breaking.json
//
//	# Once, by a human, to author the declaration that then gets reviewed.
//	reviewed-breaking -findings build/breaking.json -write release/reviewed-breaking.json \
//	  -version v0.2.0 -against v0.1.1 -review 'ADR-0013 bus envelope V2'
//
// A finding is identified by (path, type, message) and never by line or column:
// an unrelated edit above a deleted field would shift the line and silently
// invalidate the declaration, which would train everyone to regenerate it
// without reading it.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

const reviewedBreakingSchemaV1 = "trueopen-wire-reviewed-breaking-v1"

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)

// declaration mirrors schemas/reviewed-breaking-v1.schema.json.
type declaration struct {
	Schema string `json:"schema"`
	// ProtocolVersion is the release the declaration authorizes. It is scoped to
	// one release on purpose: carrying it forward unchanged would let the next
	// release inherit an approval nobody granted it.
	ProtocolVersion string `json:"protocol_version"`
	// Against is the git tag the findings were produced against.
	Against string `json:"against"`
	// Review names the decision that authorized the break. A reviewer follows
	// this link to check whether the findings below are what it decided.
	Review   string    `json:"review"`
	Notes    []string  `json:"notes"`
	Findings []finding `json:"findings"`
}

// finding is one buf breaking report, reduced to its stable identity.
type finding struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// bufFinding is buf's own --error-format=json record. Only the three stable
// fields are read; the position fields are deliberately dropped.
type bufFinding struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

func (f finding) key() string {
	return normalizePath(f.Path) + "\x00" + f.Type + "\x00" + f.Message
}

// normalizePath makes a finding's path platform-independent. Slash is the form
// the declaration is committed in, because a proto path in a buf module is
// always slash-separated regardless of the host that printed it.
func normalizePath(path string) string {
	return strings.ReplaceAll(path, `\`, "/")
}

func main() {
	findingsPath := flag.String("findings", "", "buf breaking --error-format=json output to check")
	declarationPath := flag.String("declaration", "release/reviewed-breaking.json", "committed declaration path")
	writePath := flag.String("write", "", "author a declaration from -findings instead of checking against one")
	version := flag.String("version", "", "protocol version the declaration authorizes, with -write")
	against := flag.String("against", "", "git tag the findings were produced against, with -write")
	review := flag.String("review", "", "the decision that authorized the break, with -write")
	baseline := flag.Bool("baseline", false, "print the declaration's baseline tag and exit, so CI and the declaration cannot disagree about it")
	bufExitCode := flag.Int("buf-exit-code", -1, "exit status buf breaking returned, so a buf failure cannot be read as a clean run")
	releaseVersion := flag.String("release-version", "", "version being released; a declaration authorizing a different one is rejected")
	subset := flag.Bool("subset", false, "require only that every finding is declared, without requiring every declared finding to fire; for checking a ref that already carries part of the declared break")
	flag.Parse()

	if *baseline {
		if err := printBaseline(*declarationPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(*findingsPath, *declarationPath, *writePath, *version, *against, *review,
		*bufExitCode, *releaseVersion, *subset); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// printBaseline exists so the workflow does not have to parse this file itself.
// If CI picked the baseline independently, it could check against one ref while
// the declaration authorized findings produced against another, and the exact
// match would then prove nothing.
func printBaseline(declarationPath string) error {
	value, err := readDeclaration(declarationPath)
	if err != nil {
		return err
	}
	fmt.Println(value.Against)
	return nil
}

func run(findingsPath, declarationPath, writePath, version, against, review string,
	bufExitCode int, releaseVersion string, subset bool) error {
	if findingsPath == "" {
		return errors.New("-findings is required")
	}
	observed, err := readFindings(findingsPath)
	if err != nil {
		return err
	}
	if err := reconcileBufExit(bufExitCode, len(observed)); err != nil {
		return err
	}

	if writePath != "" {
		return write(writePath, version, against, review, observed)
	}
	return check(declarationPath, observed, releaseVersion, subset)
}

// reconcileBufExit closes the gap between "buf found nothing" and "buf never
// ran". buf writes findings to stdout and exits non-zero; if it fails for any
// other reason - an unresolvable ref, a bad module - stdout is empty and the
// file looks exactly like a clean run. Cross-checking the exit status against
// the finding count is what stops a broken invocation from passing the gate.
//
// The rule avoids hardcoding buf's violation exit code, which is not something
// this repository controls: a non-zero exit has to have produced findings, and a
// zero exit must not have.
func reconcileBufExit(exitCode, findingCount int) error {
	switch {
	case exitCode < 0:
		return nil // caller did not report one; -write from a saved file is the usual case
	case exitCode == 0 && findingCount > 0:
		return fmt.Errorf("buf breaking exited 0 but reported %d finding(s); the findings file does not belong to that run", findingCount)
	case exitCode != 0 && findingCount == 0:
		return fmt.Errorf("buf breaking exited %d and reported no findings, so it failed before checking anything; "+
			"an empty findings file must not be read as a clean run", exitCode)
	default:
		return nil
	}
}

// check is the CI path. Against the declaration's own baseline it is
// intentionally symmetric: an undeclared finding and a declared finding that no
// longer fires are both failures, because both mean the committed declaration no
// longer describes the code it authorizes.
//
// subset relaxes only the second half, for the second comparison a pull request
// makes: against main. Once the declared break is merged, main already carries
// most of it and those findings correctly stop firing there, so requiring them
// would fail every later pull request. What must still hold is the first half -
// nothing breaks that the declaration does not name - and that is the half the
// baseline comparison cannot supply on its own, because a field introduced after
// the baseline tag is invisible to it and can be deleted again unnoticed.
func check(declarationPath string, observed []finding, releaseVersion string, subset bool) error {
	declared, err := readDeclaration(declarationPath)
	if err != nil {
		// No declaration means no reviewed break is claimed, so the ordinary rule
		// applies: any finding at all is a failure.
		if os.IsNotExist(err) {
			if len(observed) == 0 {
				fmt.Println("buf breaking reported no findings and no reviewed break is declared")
				return nil
			}
			return fmt.Errorf("buf breaking reported %d findings and %s does not exist: "+
				"a break has to be declared and reviewed before it can pass",
				len(observed), declarationPath)
		}
		return err
	}

	// An approval is granted for one release. Without this, tagging v0.3.0 with
	// v0.2.0's declaration still on disk would inherit an authorization nobody
	// granted, and the exact-match check would happily confirm the same findings.
	if releaseVersion != "" && declared.ProtocolVersion != releaseVersion {
		return fmt.Errorf("%s authorizes a break for %s, but the release is %s: "+
			"a reviewed break is not inherited by a later version",
			declarationPath, declared.ProtocolVersion, releaseVersion)
	}

	declaredKeys := make(map[string]finding, len(declared.Findings))
	for _, entry := range declared.Findings {
		declaredKeys[entry.key()] = entry
	}
	observedKeys := make(map[string]struct{}, len(observed))
	var undeclared []finding
	for _, entry := range observed {
		observedKeys[entry.key()] = struct{}{}
		if _, ok := declaredKeys[entry.key()]; !ok {
			undeclared = append(undeclared, entry)
		}
	}
	var stale []finding
	if !subset {
		for _, entry := range declared.Findings {
			if _, ok := observedKeys[entry.key()]; !ok {
				stale = append(stale, entry)
			}
		}
	}

	var problems []string
	if len(undeclared) > 0 {
		problems = append(problems, fmt.Sprintf("%d breaking finding(s) are not covered by %s (review %s):\n%s",
			len(undeclared), declarationPath, declared.Review, render(undeclared)))
	}
	if len(stale) > 0 {
		problems = append(problems, fmt.Sprintf("%d declared finding(s) no longer occur, so %s is stale:\n%s",
			len(stale), declarationPath, render(stale)))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}

	if subset {
		fmt.Printf("reviewed breaking release %s: all %d observed finding(s) are named by the declaration (%s)\n",
			declared.ProtocolVersion, len(observed), declared.Review)
		return nil
	}
	fmt.Printf("reviewed breaking release %s against %s: %d declared finding(s) matched exactly (%s)\n",
		declared.ProtocolVersion, declared.Against, len(declared.Findings), declared.Review)
	return nil
}

func write(writePath, version, against, review string, observed []finding) error {
	if !versionPattern.MatchString(version) {
		return fmt.Errorf("-version %q is not a semantic version", version)
	}
	if !versionPattern.MatchString(against) {
		return fmt.Errorf("-against %q is not a semantic version tag", against)
	}
	if strings.TrimSpace(review) == "" {
		return errors.New("-review must name the decision that authorized the break")
	}
	if len(observed) == 0 {
		return errors.New("buf breaking reported no findings, so there is no reviewed break to declare")
	}
	value := declaration{
		Schema:          reviewedBreakingSchemaV1,
		ProtocolVersion: version,
		Against:         against,
		Review:          review,
		Notes: []string{
			"This file is the only thing that lets a buf breaking failure pass. It authorizes exactly the findings listed below, for exactly this protocol_version, against exactly this baseline.",
			"tools/reviewed-breaking checks the set both ways: an undeclared finding fails the build, and a declared finding that no longer occurs fails it too, so the list cannot drift away from the code it describes.",
			"Findings are identified by (path, type, message) and carry no line or column, because an unrelated edit above a deleted field would otherwise invalidate the declaration and turn regenerating it into a reflex.",
			"After this release is tagged, the next one starts from a new baseline: delete this file, or replace it with a declaration naming its own version and review. Carrying it forward unchanged would grant an approval nobody asked for.",
		},
		Findings: sortFindings(observed),
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(writePath, append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	digest := sha256.Sum256(append(encoded, '\n'))
	fmt.Printf("wrote %s: %d finding(s) for %s against %s, sha256 %s\n",
		writePath, len(value.Findings), version, against, hex.EncodeToString(digest[:]))
	return nil
}

func render(findings []finding) string {
	lines := make([]string, 0, len(findings))
	for _, entry := range sortFindings(findings) {
		lines = append(lines, fmt.Sprintf("  %s: %s: %s", entry.Path, entry.Type, entry.Message))
	}
	return strings.Join(lines, "\n")
}

func sortFindings(findings []finding) []finding {
	out := append([]finding(nil), findings...)
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// readFindings parses buf's newline-delimited JSON. An empty file is the normal
// "no findings" case, not an error.
func readFindings(path string) ([]finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []finding
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	// buf messages are long; the default 64 KiB token limit is not generous
	// enough to rely on when a message enumerates a whole message's fields.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var raw bufFinding
		if err := json.Unmarshal([]byte(text), &raw); err != nil {
			return nil, fmt.Errorf("%s line %d is not a buf JSON finding: %w", path, line, err)
		}
		if strings.TrimSpace(raw.Type) == "" || strings.TrimSpace(raw.Message) == "" {
			return nil, fmt.Errorf("%s line %d has no type or message, so it cannot be declared or matched", path, line)
		}
		// buf reports the path with the host separator, so the same finding reads
		// as "proto\a.proto" on Windows and "proto/a.proto" in CI. Normalizing
		// here is what lets a declaration authored on one platform be checked on
		// the other; without it every Linux run would report the whole set as
		// undeclared.
		entry := finding{Path: normalizePath(raw.Path), Type: raw.Type, Message: raw.Message}
		// buf reports one finding per position, so the same (path, type, message)
		// can appear twice. Set semantics are what the declaration expresses, and
		// collapsing here keeps a duplicate from reading as a mismatch.
		if _, exists := seen[entry.key()]; exists {
			continue
		}
		seen[entry.key()] = struct{}{}
		findings = append(findings, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func readDeclaration(path string) (declaration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return declaration{}, err
	}
	var value declaration
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return declaration{}, fmt.Errorf("decode %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return declaration{}, fmt.Errorf("decode trailing data in %s: %w", path, err)
		}
		return declaration{}, fmt.Errorf("%s contains multiple JSON values", path)
	}
	if value.Schema != reviewedBreakingSchemaV1 {
		return declaration{}, fmt.Errorf("unsupported reviewed-breaking schema %q", value.Schema)
	}
	if !versionPattern.MatchString(value.ProtocolVersion) {
		return declaration{}, fmt.Errorf("protocol_version %q is not a semantic version", value.ProtocolVersion)
	}
	if !versionPattern.MatchString(value.Against) {
		return declaration{}, fmt.Errorf("against %q is not a semantic version tag", value.Against)
	}
	if strings.TrimSpace(value.Review) == "" {
		return declaration{}, fmt.Errorf("%s must name the decision that authorized the break", path)
	}
	if len(value.Notes) == 0 {
		return declaration{}, fmt.Errorf("%s must explain what it authorizes", path)
	}
	if len(value.Findings) == 0 {
		return declaration{}, fmt.Errorf("%s declares no findings, so it authorizes nothing and should be deleted", path)
	}
	seen := make(map[string]struct{}, len(value.Findings))
	for i, entry := range value.Findings {
		if strings.TrimSpace(entry.Type) == "" || strings.TrimSpace(entry.Message) == "" {
			return declaration{}, fmt.Errorf("%s finding %d has no type or message", path, i)
		}
		if _, exists := seen[entry.key()]; exists {
			return declaration{}, fmt.Errorf("%s declares the same finding twice: %s %s", path, entry.Path, entry.Type)
		}
		seen[entry.key()] = struct{}{}
	}
	// Sorted order is what makes a diff of this file readable, which is the whole
	// point of committing it rather than passing findings on a command line.
	if strings.Join(keys(value.Findings), "\x00") != strings.Join(keys(sortFindings(value.Findings)), "\x00") {
		return declaration{}, fmt.Errorf("%s findings must be sorted by path, type and message", path)
	}
	return value, nil
}

func keys(findings []finding) []string {
	out := make([]string, 0, len(findings))
	for _, entry := range findings {
		out = append(out, entry.key())
	}
	return out
}
