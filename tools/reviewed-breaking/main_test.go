package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bufLine(t *testing.T, path, ruleType, message string) string {
	t.Helper()
	// buf emits more fields than the three that matter; including the position
	// fields here proves the parser drops them rather than merely ignoring a
	// simplified fixture it was written against.
	encoded, err := json.Marshal(map[string]any{
		"path": path, "start_line": 12, "start_column": 3,
		"end_line": 12, "end_column": 40, "type": ruleType, "message": message,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func writeValidDeclaration(t *testing.T, path string, findings ...finding) {
	t.Helper()
	value := declaration{
		Schema:          reviewedBreakingSchemaV1,
		ProtocolVersion: "v0.2.0",
		Against:         "v0.1.1",
		Review:          "ADR-0013 bus envelope V2",
		Notes:           []string{"authorizes exactly these findings"},
		Findings:        sortFindings(findings),
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCheckMatchesDeclaredFindingsExactly is the whole point of the tool: the
// comparison is symmetric. An undeclared finding is an unreviewed break, and a
// declared finding that no longer occurs means the file no longer describes the
// code it authorizes - so both fail, and only an exact match passes.
func TestCheckMatchesDeclaredFindingsExactly(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")

	deleted := finding{Path: "hub/v1/common.proto", Type: "ENUM_NO_DELETE", Message: `Enum "ParticipantType" was deleted.`}
	moved := finding{Path: "task/v1/event.proto", Type: "FIELD_SAME_TYPE", Message: `Field "7" changed type.`}

	writeValidDeclaration(t, declarationPath, deleted, moved)
	writeLines(t, findingsPath,
		bufLine(t, deleted.Path, deleted.Type, deleted.Message),
		bufLine(t, moved.Path, moved.Type, moved.Message),
	)
	if err := run(findingsPath, declarationPath, "", "", "", "", -1, "", false); err != nil {
		t.Fatalf("exactly declared findings rejected: %v", err)
	}

	// One extra break slipped into the same commit.
	writeLines(t, findingsPath,
		bufLine(t, deleted.Path, deleted.Type, deleted.Message),
		bufLine(t, moved.Path, moved.Type, moved.Message),
		bufLine(t, "hub/v1/reward.proto", "FIELD_NO_DELETE", `Previously present field "9" was deleted.`),
	)
	err := run(findingsPath, declarationPath, "", "", "", "", -1, "", false)
	if err == nil {
		t.Fatal("an undeclared finding passed")
	}
	if !strings.Contains(err.Error(), "not covered") {
		t.Fatalf("undeclared finding reported as %v", err)
	}

	// The declaration outlived the break it described.
	writeLines(t, findingsPath, bufLine(t, deleted.Path, deleted.Type, deleted.Message))
	err = run(findingsPath, declarationPath, "", "", "", "", -1, "", false)
	if err == nil {
		t.Fatal("a stale declaration passed")
	}
	if !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale declaration reported as %v", err)
	}
}

// TestCheckWithoutDeclarationKeepsTheOrdinaryGate confirms the mechanism is
// opt-in per release: with no declaration on disk, any finding is still a
// failure, so removing the file restores the plain rule rather than disabling it.
func TestCheckWithoutDeclarationKeepsTheOrdinaryGate(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "absent.json")

	writeLines(t, findingsPath, "")
	if err := run(findingsPath, declarationPath, "", "", "", "", -1, "", false); err != nil {
		t.Fatalf("clean run with no declaration rejected: %v", err)
	}

	writeLines(t, findingsPath, bufLine(t, "a.proto", "FIELD_NO_DELETE", "field 1 was deleted"))
	if err := run(findingsPath, declarationPath, "", "", "", "", -1, "", false); err == nil {
		t.Fatal("an undeclared break passed with no declaration present")
	}
}

// TestFindingIdentityIgnoresPosition pins the identity choice. If line numbers
// were part of it, an unrelated edit above a deleted field would invalidate the
// declaration and make regenerating it a reflex instead of a review.
func TestFindingIdentityIgnoresPosition(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	entry := finding{Path: "a.proto", Type: "FIELD_NO_DELETE", Message: "field 1 was deleted"}
	writeValidDeclaration(t, declarationPath, entry)

	shifted, err := json.Marshal(map[string]any{
		"path": entry.Path, "start_line": 999, "start_column": 1,
		"type": entry.Type, "message": entry.Message,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeLines(t, findingsPath, string(shifted))
	if err := run(findingsPath, declarationPath, "", "", "", "", -1, "", false); err != nil {
		t.Fatalf("a finding at a different position was treated as a different finding: %v", err)
	}
}

// TestReadFindingsCollapsesDuplicates covers buf reporting one rule twice at two
// positions. The declaration expresses a set, so a duplicate must not read as a
// mismatch against it.
func TestReadFindingsCollapsesDuplicates(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	line := bufLine(t, "a.proto", "FIELD_NO_DELETE", "field 1 was deleted")
	writeLines(t, findingsPath, line, line, "", line)

	findings, err := readFindings(findingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
}

// TestBufExitCodeIsReconciledWithTheFindings covers the failure mode that would
// have made the whole gate decorative: buf writes findings to stdout, so a buf
// invocation that dies before checking anything - unresolvable ref, broken
// module - leaves a file indistinguishable from a clean run.
func TestBufExitCodeIsReconciledWithTheFindings(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	entry := finding{Path: "a.proto", Type: "FIELD_NO_DELETE", Message: "field 1 was deleted"}
	writeValidDeclaration(t, declarationPath, entry)

	// buf failed for a non-violation reason: empty output, non-zero exit.
	writeLines(t, findingsPath, "")
	err := run(findingsPath, declarationPath, "", "", "", "", 1, "", false)
	if err == nil {
		t.Fatal("a buf failure with no findings passed the gate")
	}
	if !strings.Contains(err.Error(), "failed before checking anything") {
		t.Fatalf("buf failure reported as %v", err)
	}

	// Findings present but buf claims success: the file is from another run.
	writeLines(t, findingsPath, bufLine(t, entry.Path, entry.Type, entry.Message))
	if err := run(findingsPath, declarationPath, "", "", "", "", 0, "", false); err == nil {
		t.Fatal("a findings file that does not belong to the reported run passed")
	}

	// The two consistent combinations.
	if err := run(findingsPath, declarationPath, "", "", "", "", 100, "", false); err != nil {
		t.Fatalf("violations with a non-zero exit rejected: %v", err)
	}
	writeLines(t, findingsPath, "")
	if err := run(findingsPath, filepath.Join(root, "absent.json"), "", "", "", "", 0, "", false); err != nil {
		t.Fatalf("a clean run rejected: %v", err)
	}
}

// TestApprovalIsNotInheritedByALaterVersion covers the stale-declaration case
// that CI would otherwise hit on release day: v0.2.0's approval still on disk
// while v0.3.0 is being tagged. The findings would still match exactly, so the
// exact-match check alone would confirm an authorization nobody granted.
func TestApprovalIsNotInheritedByALaterVersion(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	entry := finding{Path: "a.proto", Type: "FIELD_NO_DELETE", Message: "field 1 was deleted"}
	writeValidDeclaration(t, declarationPath, entry)
	writeLines(t, findingsPath, bufLine(t, entry.Path, entry.Type, entry.Message))

	if err := run(findingsPath, declarationPath, "", "", "", "", 100, "v0.2.0", false); err != nil {
		t.Fatalf("the release the declaration authorizes was rejected: %v", err)
	}
	err := run(findingsPath, declarationPath, "", "", "", "", 100, "v0.3.0", false)
	if err == nil {
		t.Fatal("a later release inherited the approval")
	}
	if !strings.Contains(err.Error(), "not inherited") {
		t.Fatalf("inherited approval reported as %v", err)
	}
}

func TestPrintBaselineRequiresAReadableDeclaration(t *testing.T) {
	root := t.TempDir()
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	if err := printBaseline(declarationPath); err == nil {
		t.Fatal("printed a baseline with no declaration on disk")
	}
	writeValidDeclaration(t, declarationPath,
		finding{Path: "a.proto", Type: "FIELD_NO_DELETE", Message: "field 1 was deleted"})
	if err := printBaseline(declarationPath); err != nil {
		t.Fatalf("valid declaration rejected: %v", err)
	}
}

func TestReadFindingsRejectsUnusableInput(t *testing.T) {
	root := t.TempDir()
	for _, testCase := range []struct{ name, content string }{
		{"not JSON", "buf: something went wrong"},
		{"a finding with no type", `{"path":"a.proto","message":"m"}`},
		{"a finding with no message", `{"path":"a.proto","type":"FIELD_NO_DELETE"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(root, "breaking.json")
			writeLines(t, path, testCase.content)
			if _, err := readFindings(path); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestWriteAuthorsASortedDeclaration(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	writeLines(t, findingsPath,
		bufLine(t, "z.proto", "FIELD_NO_DELETE", "field 2 was deleted"),
		bufLine(t, "a.proto", "ENUM_NO_DELETE", "enum X was deleted"),
	)

	if err := run(findingsPath, declarationPath, declarationPath, "v0.2.0", "v0.1.1", "ADR-0013 bus envelope V2", -1, "", false); err != nil {
		t.Fatalf("write: %v", err)
	}
	value, err := readDeclaration(declarationPath)
	if err != nil {
		t.Fatalf("the tool wrote a declaration it cannot read back: %v", err)
	}
	if len(value.Findings) != 2 || value.Findings[0].Path != "a.proto" {
		t.Fatalf("declaration findings are not sorted: %+v", value.Findings)
	}
	if err := run(findingsPath, declarationPath, "", "", "", "", -1, "", false); err != nil {
		t.Fatalf("the authored declaration does not satisfy its own check: %v", err)
	}
}

// schemas/reviewed-breaking-v1.schema.json is what a consumer reads to check a
// declaration published as a release asset. Nothing else validates against it,
// so without this test the schema and the struct that actually writes the file
// can drift apart and the published schema would reject - or silently permit -
// a declaration this tool considers valid. Both sides set additionalProperties
// false, which makes the comparison exact rather than approximate.
func TestWrittenDeclarationMatchesThePublishedSchema(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	writeLines(t, findingsPath, bufLine(t, "a.proto", "ENUM_NO_DELETE", "enum X was deleted"))
	if err := run(findingsPath, "", declarationPath, "v0.2.0", "v0.1.1", "ADR-0013 bus envelope V2", -1, "", false); err != nil {
		t.Fatalf("write: %v", err)
	}

	var schema struct {
		AdditionalProperties *bool               `json:"additionalProperties"`
		Required             []string            `json:"required"`
		Properties           map[string]struct { // only findings.items is inspected below
			Items struct {
				AdditionalProperties *bool               `json:"additionalProperties"`
				Required             []string            `json:"required"`
				Properties           map[string]struct{} `json:"properties"`
			} `json:"items"`
		} `json:"properties"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "reviewed-breaking-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	var written struct {
		Top      map[string]json.RawMessage
		Findings []map[string]json.RawMessage
	}
	authored, err := os.ReadFile(declarationPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(authored, &written.Top); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(written.Top["findings"], &written.Findings); err != nil {
		t.Fatal(err)
	}

	compare := func(label string, closed *bool, required []string, declared map[string]struct{}, got map[string]json.RawMessage) {
		t.Helper()
		if closed == nil || *closed {
			for key := range got {
				if _, ok := declared[key]; !ok {
					t.Errorf("%s: the tool writes %q, which the schema forbids", label, key)
				}
			}
		}
		for key := range declared {
			if _, ok := got[key]; !ok {
				t.Errorf("%s: the schema declares %q, which the tool never writes", label, key)
			}
		}
		for _, key := range required {
			if _, ok := got[key]; !ok {
				t.Errorf("%s: the schema requires %q, which the tool never writes", label, key)
			}
		}
	}

	topProperties := map[string]struct{}{}
	for key := range schema.Properties {
		topProperties[key] = struct{}{}
	}
	compare("declaration", schema.AdditionalProperties, schema.Required, topProperties, written.Top)

	items := schema.Properties["findings"].Items
	if len(written.Findings) == 0 {
		t.Fatal("the authored declaration has no finding to compare")
	}
	compare("finding", items.AdditionalProperties, items.Required, items.Properties, written.Findings[0])
}

func TestWriteRejectsUnusableArguments(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	writeLines(t, findingsPath, bufLine(t, "a.proto", "FIELD_NO_DELETE", "field 1 was deleted"))
	emptyPath := filepath.Join(root, "empty.json")
	writeLines(t, emptyPath, "")

	for _, testCase := range []struct {
		name                             string
		findings, version, against, note string
	}{
		{"no version", findingsPath, "", "v0.1.1", "review"},
		{"no baseline", findingsPath, "v0.2.0", "", "review"},
		{"no review", findingsPath, "v0.2.0", "v0.1.1", "  "},
		{"nothing to authorize", emptyPath, "v0.2.0", "v0.1.1", "review"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			out := filepath.Join(root, "out.json")
			err := run(testCase.findings, "", out, testCase.version, testCase.against, testCase.note, -1, "", false)
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestReadDeclarationRejectsUnusableFiles(t *testing.T) {
	root := t.TempDir()
	base := func() map[string]any {
		return map[string]any{
			"schema": reviewedBreakingSchemaV1, "protocol_version": "v0.2.0",
			"against": "v0.1.1", "review": "r", "notes": []string{"n"},
			"findings": []map[string]string{
				{"path": "a.proto", "type": "ENUM_NO_DELETE", "message": "m"},
				{"path": "z.proto", "type": "FIELD_NO_DELETE", "message": "m"},
			},
		}
	}
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"accepts a well-formed declaration", nil},
		{"rejects a wrong schema", func(v map[string]any) { v["schema"] = "something-else" }},
		{"rejects a non-semver version", func(v map[string]any) { v["protocol_version"] = "0.2" }},
		{"rejects a non-semver baseline", func(v map[string]any) { v["against"] = "main" }},
		{"rejects a missing review", func(v map[string]any) { v["review"] = " " }},
		{"rejects missing notes", func(v map[string]any) { v["notes"] = []string{} }},
		{"rejects an empty finding set", func(v map[string]any) { v["findings"] = []map[string]string{} }},
		{"rejects unsorted findings", func(v map[string]any) {
			findings := v["findings"].([]map[string]string)
			findings[0], findings[1] = findings[1], findings[0]
		}},
		{"rejects duplicate findings", func(v map[string]any) {
			findings := v["findings"].([]map[string]string)
			findings[1] = findings[0]
		}},
		{"rejects a finding with no type", func(v map[string]any) {
			v["findings"].([]map[string]string)[0]["type"] = ""
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value := base()
			if testCase.mutate != nil {
				testCase.mutate(value)
			}
			encoded, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "declaration.json")
			if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = readDeclaration(path)
			if testCase.mutate == nil {
				if err != nil {
					t.Fatalf("valid declaration rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// TestFindingPathIsPlatformIndependent covers the declaration being authored on
// one host and checked on another. buf prints the host separator, so without
// normalization a declaration written on Windows would report every finding as
// undeclared when CI re-ran it on Linux - and the natural response would be to
// regenerate the file rather than to notice why.
func TestFindingPathIsPlatformIndependent(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")

	// Declared with slashes, as committed.
	entry := finding{Path: "proto/hub/v1/common.proto", Type: "ENUM_NO_DELETE", Message: `Enum "Duty" was deleted.`}
	writeValidDeclaration(t, declarationPath, entry)

	// Reported with backslashes, as a Windows buf run prints them.
	writeLines(t, findingsPath, bufLine(t, `proto\hub\v1\common.proto`, entry.Type, entry.Message))
	if err := run(findingsPath, declarationPath, "", "", "", "", 100, "", false); err != nil {
		t.Fatalf("a backslash path did not match its slash declaration: %v", err)
	}

	// And a declaration that somehow carries backslashes still matches a slash
	// report, so an older committed file does not become unusable.
	writeValidDeclaration(t, declarationPath, finding{
		Path: `proto\hub\v1\common.proto`, Type: entry.Type, Message: entry.Message})
	writeLines(t, findingsPath, bufLine(t, entry.Path, entry.Type, entry.Message))
	if err := run(findingsPath, declarationPath, "", "", "", "", 100, "", false); err != nil {
		t.Fatalf("a slash report did not match a backslash declaration: %v", err)
	}
}

// TestSubsetChecksMainWithoutRequiringTheWholeDeclaration covers the second
// comparison a pull request makes. The baseline comparison alone leaves one
// hole: a field added by the release under review does not exist at the baseline
// tag, so deleting it again before the tag is cut produces no finding there and
// nobody is told. Comparing against main closes it - but main carries the
// declared break once it merges, so the declared findings correctly stop firing
// there and the exact match would fail every later pull request.
func TestSubsetChecksMainWithoutRequiringTheWholeDeclaration(t *testing.T) {
	root := t.TempDir()
	findingsPath := filepath.Join(root, "breaking.json")
	declarationPath := filepath.Join(root, "reviewed-breaking.json")
	declared := finding{Path: "a.proto", Type: "FIELD_NO_DELETE", Message: "field 1 was deleted"}
	writeValidDeclaration(t, declarationPath, declared)

	// Against main after the break merged: nothing fires, and that is correct.
	writeLines(t, findingsPath, "")
	if err := run(findingsPath, declarationPath, "", "", "", "", 0, "", true); err != nil {
		t.Fatalf("subset rejected a clean run against main: %v", err)
	}
	if err := run(findingsPath, declarationPath, "", "", "", "", 0, "", false); err == nil {
		t.Fatal("the exact match accepted a run in which no declared finding fired")
	}

	// A field this release added and a later pull request deletes. The baseline
	// tag cannot see it; main can, and it is not in the declaration.
	writeLines(t, findingsPath, bufLine(t, "b.proto", "FIELD_NO_DELETE", "field 7 was deleted"))
	if err := run(findingsPath, declarationPath, "", "", "", "", 100, "", true); err == nil {
		t.Fatal("subset accepted a break that the declaration does not name")
	}

	// The declared break itself, seen against a main that does not yet carry it.
	writeLines(t, findingsPath, bufLine(t, declared.Path, declared.Type, declared.Message))
	if err := run(findingsPath, declarationPath, "", "", "", "", 100, "", true); err != nil {
		t.Fatalf("subset rejected the declared finding: %v", err)
	}
}
