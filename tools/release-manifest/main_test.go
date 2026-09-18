package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const validCommit = "0123456789abcdef0123456789abcdef01234567"

// TestManifestFieldsMatchTheSchema is why schemas/ stops being decoration.
//
// The four documents under schemas/ were consumed by nothing: verify-fixtures,
// verify-registry and this tool all validate with hand-written Go structs, so the
// schema and the code were two independent statements of one contract with
// nothing comparing them - the shape the golden vectors and the registry export
// exist to remove everywhere else in this repository.
//
// A full JSON Schema validator would mean a third-party dependency in a module
// that has none. Comparing the field sets does not: it catches the drift that
// actually happens (a key added to one side, a required key that became
// optional), needs only encoding/json and reflect, and fails on the file rather
// than on a downstream consumer.
func TestManifestFieldsMatchTheSchema(t *testing.T) {
	schema := readSchema(t, "../../schemas/release-manifest-v1.schema.json")

	assertObjectMatchesStruct(t, "release manifest", schema, reflect.TypeOf(releaseManifest{}))

	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema has no $defs")
	}
	artifactSchema, ok := defs["artifact"].(map[string]any)
	if !ok {
		t.Fatal("schema $defs has no artifact")
	}
	assertObjectMatchesStruct(t, "artifact", artifactSchema, reflect.TypeOf(artifact{}))

	properties, _ := schema["properties"].(map[string]any)
	compatSchema, ok := properties["compatibility"].(map[string]any)
	if !ok {
		t.Fatal("schema has no compatibility object")
	}
	assertObjectMatchesStruct(t, "compatibility", compatSchema, reflect.TypeOf(compatibility{}))

	compatProperties := compatSchema["properties"].(map[string]any)
	reviewedSchema, ok := compatProperties["reviewed_breaking"].(map[string]any)
	if !ok {
		t.Fatal("compatibility has no reviewed_breaking object")
	}
	assertObjectMatchesStruct(t, "reviewed_breaking", reviewedSchema, reflect.TypeOf(reviewedBreaking{}))

	// The one value constraint worth pinning by hand: buildCompatibility branches on
	// exactly these results, so a fourth one added to the schema would silently be
	// rejected by the tool.
	enum := stringSlice(t, compatProperties["result"].(map[string]any)["enum"])
	if strings.Join(enum, ",") != "bootstrap,pass,reviewed-breaking" {
		t.Fatalf("compatibility.result enum is %v; buildCompatibility implements bootstrap, pass and reviewed-breaking", enum)
	}
}

// TestReviewedBreakingCompatibility covers the result that exists so a breaking
// release does not have to lie. Each rejection below is a way of publishing an
// incompatible release while the manifest still reads like a compatible one.
func TestReviewedBreakingCompatibility(t *testing.T) {
	root := writeFakeRepo(t)
	const declarationPath = "release/reviewed-breaking.json"
	writeDeclaration := func(t *testing.T, value map[string]any) {
		t.Helper()
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "release", "reviewed-breaking.json"), append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	validDeclaration := func() map[string]any {
		return map[string]any{
			"schema":           "trueopen-wire-reviewed-breaking-v1",
			"protocol_version": "v0.2.0",
			"against":          "v0.1.1",
			"review":           "TrueOpen/monorepo#74",
			"notes":            []string{"authorizes exactly these findings"},
			"findings": []map[string]string{
				{"path": "a.proto", "type": "FIELD_NO_DELETE", "message": "field 5 was deleted"},
			},
		}
	}

	writeDeclaration(t, validDeclaration())
	compat, err := buildCompatibility(root, "reviewed-breaking", "v0.1.1", declarationPath)
	if err != nil {
		t.Fatalf("valid reviewed-breaking rejected: %v", err)
	}
	if compat.ReviewedBreaking == nil || compat.ReviewedBreaking.FindingCount != 1 ||
		compat.ReviewedBreaking.Review != "TrueOpen/monorepo#74" {
		t.Fatalf("reviewed_breaking block is %+v", compat.ReviewedBreaking)
	}
	if err := verifyCompatibility(root, compat); err != nil {
		t.Fatalf("round-trip verify: %v", err)
	}

	// The digest in the manifest has to be worth something: editing the
	// declaration after the manifest was written must fail verification.
	tampered := validDeclaration()
	tampered["review"] = "some other issue"
	writeDeclaration(t, tampered)
	if err := verifyCompatibility(root, compat); err == nil {
		t.Fatal("an edited declaration passed verification")
	}
	writeDeclaration(t, validDeclaration())

	for _, testCase := range []struct {
		name                     string
		result, against, declare string
	}{
		{"reviewed-breaking without a declaration", "reviewed-breaking", "v0.1.1", ""},
		{"reviewed-breaking without a baseline", "reviewed-breaking", "", declarationPath},
		{"reviewed-breaking against the wrong baseline", "reviewed-breaking", "v0.1.0", declarationPath},
		{"pass that also claims a reviewed break", "pass", "v0.1.1", declarationPath},
		{"bootstrap that also claims a reviewed break", "bootstrap", "", declarationPath},
		{"a declaration that does not exist", "reviewed-breaking", "v0.1.1", "release/missing.json"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := buildCompatibility(root, testCase.result, testCase.against, testCase.declare); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	// A reviewed_breaking block hanging off a "pass" result is the specific lie
	// this result exists to prevent, so verify has to catch it even though the
	// writer would never emit it.
	mislabeled := compat
	mislabeled.Result = "pass"
	if err := verifyCompatibility(root, mislabeled); err == nil {
		t.Fatal("a pass result carrying a reviewed_breaking block passed verification")
	}
}

// assertObjectMatchesStruct compares one schema object node with the Go struct
// that decodes it: the property names must be exactly the struct's JSON names,
// and the required set must be exactly the JSON names that are NOT omitempty.
func assertObjectMatchesStruct(t *testing.T, label string, node map[string]any, structType reflect.Type) {
	t.Helper()

	properties, ok := node["properties"].(map[string]any)
	if !ok {
		t.Fatalf("%s: schema node has no properties", label)
	}
	schemaProperties := make([]string, 0, len(properties))
	for name := range properties {
		schemaProperties = append(schemaProperties, name)
	}
	sort.Strings(schemaProperties)

	var goProperties, goRequired []string
	for i := 0; i < structType.NumField(); i++ {
		tag := structType.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		goProperties = append(goProperties, name)
		optional := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				optional = true
			}
		}
		if !optional {
			goRequired = append(goRequired, name)
		}
	}
	sort.Strings(goProperties)
	sort.Strings(goRequired)

	if strings.Join(schemaProperties, ",") != strings.Join(goProperties, ",") {
		t.Fatalf("%s: schema properties %v do not match struct JSON fields %v", label, schemaProperties, goProperties)
	}

	// additionalProperties:false plus a matching property set is what makes the
	// Go decoder's DisallowUnknownFields and the schema agree about rejection.
	if additional, present := node["additionalProperties"]; !present || additional != false {
		t.Fatalf("%s: schema must set additionalProperties:false to match DisallowUnknownFields", label)
	}

	schemaRequired := stringSlice(t, node["required"])
	sort.Strings(schemaRequired)
	if strings.Join(schemaRequired, ",") != strings.Join(goRequired, ",") {
		t.Fatalf("%s: schema required %v does not match the non-omitempty struct fields %v",
			label, schemaRequired, goRequired)
	}
}

func TestGenerateThenVerifyRoundTrip(t *testing.T) {
	root := writeFakeRepo(t)
	manifestPath := filepath.Join(root, "build", "release-manifest.json")

	if err := run(root, "", manifestPath, validInput()); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := run(root, manifestPath, "", generateInput{}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	manifest, err := readManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(manifest.ProtoPackages, ",") != "hub.v1,task.v1" {
		t.Fatalf("proto_packages is %v; it must be the released set", manifest.ProtoPackages)
	}
	if manifest.Compatibility.Result != "bootstrap" || manifest.Compatibility.AgainstVersion != "" {
		t.Fatalf("bootstrap compatibility must name no previous version, got %+v", manifest.Compatibility)
	}
	if len(manifest.Registries) != 2 {
		t.Fatalf("every release publishes both registries, got %d", len(manifest.Registries))
	}
}

func TestVerifyRejectsTamperedArtifact(t *testing.T) {
	root := writeFakeRepo(t)
	manifestPath := filepath.Join(root, "build", "release-manifest.json")
	if err := run(root, "", manifestPath, validInput()); err != nil {
		t.Fatal(err)
	}

	// One byte appended to the descriptor after the manifest was written: exactly
	// the case a consumer downloading the release asset has to be protected from.
	descriptor := filepath.Join(root, "build", "wire.binpb")
	body, err := os.ReadFile(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptor, append(body, 0x00), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, manifestPath, "", generateInput{}); err == nil {
		t.Fatal("a tampered descriptor was accepted")
	}
}

func TestGenerateRejectsBadInput(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input generateInput
	}{
		{"non-semantic version", func() generateInput { i := validInput(); i.version = "0.1.0"; return i }()},
		{"short git commit", func() generateInput { i := validInput(); i.gitCommit = "abc"; return i }()},
		{"non-semantic buf version", func() generateInput { i := validInput(); i.bufVersion = "1.71.0"; return i }()},
		{"unknown compatibility result", func() generateInput { i := validInput(); i.result = "fail"; return i }()},
		{"bootstrap naming a previous version", func() generateInput {
			i := validInput()
			i.againstVersion = "v0.0.9"
			return i
		}()},
		{"pass without a previous version", func() generateInput { i := validInput(); i.result = "pass"; return i }()},
		{"missing descriptor", func() generateInput { i := validInput(); i.descriptorPath = "build/absent.binpb"; return i }()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := writeFakeRepo(t)
			if err := run(root, "", filepath.Join(root, "build", "m.json"), testCase.input); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

// TestReleaseScopeIsFrozenAgainstTheProtoTree is the check that keeps a narrowed
// release honest: the scope has to account for every package present, exactly
// once, so neither publishing nor withholding can happen by accident.
func TestReleaseScopeIsFrozenAgainstTheProtoTree(t *testing.T) {
	t.Run("undeclared package fails", func(t *testing.T) {
		root := writeFakeRepo(t)
		writeProto(t, root, "bus/v1/envelope.proto", "bus.v1")
		if _, err := loadReleaseScope(root); err == nil {
			t.Fatal("a package present in proto/ but absent from the scope was accepted")
		}
	})

	t.Run("declared but absent package fails", func(t *testing.T) {
		root := writeFakeRepo(t)
		writeScope(t, root, []string{"hub.v1", "task.v1", "trueopenghost.v1"}, nil)
		if _, err := loadReleaseScope(root); err == nil {
			t.Fatal("a scope naming a package that does not exist was accepted")
		}
	})

	t.Run("package in both lists fails", func(t *testing.T) {
		root := writeFakeRepo(t)
		writeScope(t, root, []string{"hub.v1", "task.v1"},
			[]withheldPackage{{Package: "task.v1", Reason: "contradiction"}})
		if _, err := loadReleaseScope(root); err == nil {
			t.Fatal("a package that is both released and withheld was accepted")
		}
	})

	t.Run("withheld package without a reason fails", func(t *testing.T) {
		root := writeFakeRepo(t)
		writeProto(t, root, "bus/v1/envelope.proto", "bus.v1")
		writeScope(t, root, []string{"hub.v1", "task.v1"},
			[]withheldPackage{{Package: "bus.v1"}})
		if _, err := loadReleaseScope(root); err == nil {
			t.Fatal("a withheld package with no reason was accepted")
		}
	})

	t.Run("withheld package with a reason passes", func(t *testing.T) {
		root := writeFakeRepo(t)
		writeProto(t, root, "bus/v1/envelope.proto", "bus.v1")
		writeScope(t, root, []string{"hub.v1", "task.v1"},
			[]withheldPackage{{Package: "bus.v1", Reason: "domain not registered upstream yet"}})
		scope, err := loadReleaseScope(root)
		if err != nil {
			t.Fatalf("a declared withholding was rejected: %v", err)
		}
		if len(scope.Released) != 2 || len(scope.Withheld) != 1 {
			t.Fatalf("unexpected scope %+v", scope)
		}
	})

	t.Run("unsorted released list fails", func(t *testing.T) {
		root := writeFakeRepo(t)
		writeScope(t, root, []string{"task.v1", "hub.v1"}, nil)
		if _, err := loadReleaseScope(root); err == nil {
			t.Fatal("an unsorted released list was accepted")
		}
	})
}

// TestCommittedReleaseScopeIsValid runs the frozen check against the real
// repository, so release/packages.json cannot drift from proto/ without a test
// failing here rather than at release time.
func TestCommittedReleaseScopeIsValid(t *testing.T) {
	scope, err := loadReleaseScope("../..")
	if err != nil {
		t.Fatalf("release/packages.json is not valid against proto/: %v", err)
	}
	if len(scope.Released) == 0 {
		t.Fatal("the committed scope releases nothing")
	}
	for _, entry := range scope.Withheld {
		if len(entry.Reason) < 40 {
			t.Fatalf("withheld package %q needs a reason a reader can act on, got %q", entry.Package, entry.Reason)
		}
	}
}

func validInput() generateInput {
	return generateInput{
		version:        "v0.1.0",
		gitCommit:      validCommit,
		bufVersion:     "v1.71.0",
		descriptorPath: "build/wire.binpb",
		result:         "bootstrap",
	}
}

// writeFakeRepo builds the minimum layout the tool reads: two proto packages, the
// two registries, the fixture manifest, a descriptor image and a matching scope.
func writeFakeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeProto(t, root, "hub/v1/common.proto", "hub.v1")
	writeProto(t, root, "task/v1/task.proto", "task.v1")
	writeFile(t, root, "registry/v1/domains.json", `{"schema":"trueopen-domain-registry-v1"}`)
	writeFile(t, root, "registry/v1/framing.json", `{"schema":"trueopen-framing-registry-v1"}`)
	writeFile(t, root, "testdata/v1/manifest.json", `{"schema":"trueopen-wire-fixture-manifest-v1"}`)
	writeFile(t, root, "build/wire.binpb", "not really a descriptor, but it has bytes")
	writeScope(t, root, []string{"hub.v1", "task.v1"}, nil)
	return root
}

func writeScope(t *testing.T, root string, released []string, withheld []withheldPackage) {
	t.Helper()
	scope := releasePackages{
		Schema:   releasePackagesSchemaV1,
		Notes:    []string{"test scope"},
		Released: released,
		Withheld: withheld,
	}
	encoded, err := json.MarshalIndent(scope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, releasePackagesPath, string(encoded))
}

func writeProto(t *testing.T, root, path, pkg string) {
	t.Helper()
	writeFile(t, root, "proto/"+path, "syntax = \"proto3\";\n\npackage "+pkg+";\n")
}

func writeFile(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	items, ok := value.([]any)
	if !ok {
		t.Fatalf("expected a JSON array, got %T", value)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("expected a string array element, got %T", item)
		}
		out = append(out, text)
	}
	return out
}
