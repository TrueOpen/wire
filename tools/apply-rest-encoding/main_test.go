package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

// The image below is the smallest one that still has all four shapes the
// projection has to get right: a Hash32 leaf bound to a URL path, a Base64 leaf
// in a query parameter, a repeated Hash32, and a nested message reached only
// through another definition.
func testImage() protoimage.Image {
	bytesField := func(name string, number int, encoding string, repeated bool) protoimage.Field {
		field := protoimage.Field{
			Name: name, Number: number, Type: protoimage.TypeBytes, Label: "LABEL_OPTIONAL",
		}
		if repeated {
			field.Label = protoimage.LabelRepeated
		}
		if encoding != "" {
			field.Options = json.RawMessage(
				`{"[shared.v1.rest_bytes_encoding]":"` + encoding + `"}`)
		}
		return field
	}
	return protoimage.Image{File: []protoimage.File{{
		Name:    "task/v1/query.proto",
		Package: "task.v1",
		MessageType: []protoimage.Message{
			{Name: "Request", Field: []protoimage.Field{
				bytesField("task_id", 1, protoimage.EncodingHash32, false),
				{Name: "page", Number: 2, Type: protoimage.TypeMessage,
					TypeName: ".task.v1.Page", Label: "LABEL_OPTIONAL"},
			}},
			{Name: "Response", Field: []protoimage.Field{
				bytesField("task_id", 1, protoimage.EncodingHash32, false),
				bytesField("digests", 2, protoimage.EncodingHash32, true),
				bytesField("blob", 3, protoimage.EncodingBase64, false),
			}},
			{Name: "Page", Field: []protoimage.Field{
				bytesField("page_token", 1, protoimage.EncodingBase64, false),
			}},
		},
		EnumType: []protoimage.Enum{{Name: "Duty"}},
		Service: []protoimage.Service{{Name: "Query", Method: []protoimage.Method{{
			Name:       "GetTask",
			InputType:  ".task.v1.Request",
			OutputType: ".task.v1.Response",
			Options: json.RawMessage(
				`{"[google.api.http]":{"get":"/v1/task/{task_id=*}"}}`),
		}}}},
	}}}
}

const testSwagger = `{
  "swagger": "2.0",
  "info": {"title": "task/v1/query.proto", "version": "version not set"},
  "paths": {
    "/v1/task/{task_id}": {
      "get": {
        "operationId": "Query_GetTask",
        "parameters": [
          {"name": "task_id", "in": "path", "required": true, "type": "string", "format": "byte"},
          {"name": "page.page_token", "in": "query", "required": false, "type": "string", "format": "byte"}
        ]
      }
    }
  },
  "definitions": {
    "task.v1.Duty": {"type": "string", "enum": ["DUTY_UNSPECIFIED"]},
    "task.v1.Response": {
      "type": "object",
      "properties": {
        "task_id": {"type": "string", "format": "byte", "description": "the task"},
        "digests": {"type": "array", "items": {"type": "string", "format": "byte"}},
        "blob": {"type": "string", "format": "byte"}
      }
    },
    "task.v1.Page": {
      "type": "object",
      "properties": {
        "page_token": {"type": "string", "format": "byte"}
      }
    }
  }
}
`

// scenario writes an image and one swagger document to a temp dir and returns
// the two paths.
func scenario(t *testing.T, img protoimage.Image, swagger string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	encoded, err := json.Marshal(img)
	if err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(dir, "image.json")
	if err := os.WriteFile(imagePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	openapiDir := filepath.Join(dir, "openapi", "task", "v1")
	if err := os.MkdirAll(openapiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(openapiDir, "query.swagger.json"), []byte(swagger), 0o600); err != nil {
		t.Fatal(err)
	}
	return imagePath, filepath.Join(dir, "openapi")
}

func readDocument(t *testing.T, openapiDir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(openapiDir, "task", "v1", "query.swagger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

// dig walks a decoded document by key, failing the test rather than panicking
// when a step is missing.
func dig(t *testing.T, node any, path ...string) map[string]any {
	t.Helper()
	current, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("expected an object at the root of %v", path)
	}
	for i, key := range path {
		next, ok := current[key]
		if !ok {
			t.Fatalf("no %q at %v", key, path[:i])
		}
		current, ok = next.(map[string]any)
		if !ok {
			t.Fatalf("%q at %v is not an object", key, path[:i])
		}
	}
	return current
}

func wantHash32(t *testing.T, schema map[string]any, where string) {
	t.Helper()
	if schema["type"] != "string" {
		t.Errorf("%s type is %v, want string", where, schema["type"])
	}
	if schema["format"] != hash32Format {
		t.Errorf("%s format is %v, want %s", where, schema["format"], hash32Format)
	}
	if schema["pattern"] != hash32Pattern {
		t.Errorf("%s pattern is %v, want %s", where, schema["pattern"], hash32Pattern)
	}
	for _, key := range []string{"minLength", "maxLength"} {
		length, ok := schema[key].(float64)
		if !ok || int(length) != hash32Length {
			t.Errorf("%s %s is %v, want %d", where, key, schema[key], hash32Length)
		}
	}
}

func TestProjectsHash32AndBase64(t *testing.T) {
	imagePath, openapiDir := scenario(t, testImage(), testSwagger)
	changed, err := apply(imagePath, openapiDir)
	if err != nil {
		t.Fatal(err)
	}
	// task_id property, digests items, blob, page_token, and the two parameters.
	if changed != 6 {
		t.Errorf("changed %d nodes, want 6", changed)
	}

	document := readDocument(t, openapiDir)
	response := dig(t, document, "definitions", "task.v1.Response", "properties")

	wantHash32(t, response["task_id"].(map[string]any), "Response.task_id")
	if description := response["task_id"].(map[string]any)["description"]; description != "the task" {
		t.Errorf("Hash32 projection dropped the description: %v", description)
	}

	digests := response["digests"].(map[string]any)
	if digests["type"] != "array" {
		t.Fatalf("digests stopped being an array: %v", digests["type"])
	}
	if _, hasFormat := digests["format"]; hasFormat {
		t.Errorf("the array wrapper itself was given a format")
	}
	wantHash32(t, digests["items"].(map[string]any), "Response.digests items")

	blob := response["blob"].(map[string]any)
	if blob["format"] != base64Format {
		t.Errorf("blob format is %v, want %s", blob["format"], base64Format)
	}
	if _, hasPattern := blob["pattern"]; hasPattern {
		t.Errorf("a Base64 leaf was given a Hash32 pattern")
	}
	if note, _ := blob["description"].(string); !strings.Contains(note, base64Note) {
		t.Errorf("Base64 leaf carries no alphabet/padding note: %q", note)
	}
}

// A path parameter is spelled inline in Swagger 2.0, so the definitions pass
// never reaches it. This is the case that matters most: a Base64 digest in a
// URL is not a digest.
func TestProjectsPathAndQueryParameters(t *testing.T) {
	imagePath, openapiDir := scenario(t, testImage(), testSwagger)
	if _, err := apply(imagePath, openapiDir); err != nil {
		t.Fatal(err)
	}
	operation := dig(t, readDocument(t, openapiDir), "paths", "/v1/task/{task_id}", "get")
	parameters, ok := operation["parameters"].([]any)
	if !ok || len(parameters) != 2 {
		t.Fatalf("expected 2 parameters, got %v", operation["parameters"])
	}

	first := parameters[0].(map[string]any)
	wantHash32(t, first, "task_id parameter")
	if first["in"] != "path" || first["required"] != true {
		t.Errorf("projection disturbed the parameter's own keys: %v", first)
	}

	second := parameters[1].(map[string]any)
	if second["format"] != base64Format {
		t.Errorf("page.page_token format is %v, want %s", second["format"], base64Format)
	}
}

// The projection has to survive being run twice, because CI runs it after every
// generate and a second run must not append the Base64 note again.
func TestIdempotent(t *testing.T) {
	imagePath, openapiDir := scenario(t, testImage(), testSwagger)
	if _, err := apply(imagePath, openapiDir); err != nil {
		t.Fatal(err)
	}
	first := readDocument(t, openapiDir)

	changed, err := apply(imagePath, openapiDir)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Errorf("second run changed %d nodes, want 0", changed)
	}
	second := readDocument(t, openapiDir)

	firstEncoded, _ := json.Marshal(first)
	secondEncoded, _ := json.Marshal(second)
	if string(firstEncoded) != string(secondEncoded) {
		t.Errorf("second run altered the document")
	}
}

// Object key order is what keeps the generated diff readable, so it is asserted
// rather than left to chance.
func TestPreservesKeyOrder(t *testing.T) {
	imagePath, openapiDir := scenario(t, testImage(), testSwagger)
	if _, err := apply(imagePath, openapiDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(openapiDir, "task", "v1", "query.swagger.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, pair := range [][2]string{
		{`"swagger"`, `"info"`},
		{`"info"`, `"paths"`},
		{`"paths"`, `"definitions"`},
		{`"task_id"`, `"digests"`}, // field order inside Response
	} {
		if strings.Index(text, pair[0]) > strings.Index(text, pair[1]) {
			t.Errorf("%s no longer precedes %s", pair[0], pair[1])
		}
	}
	// The rewritten keys go where the generator put them, not at the end.
	taskID := strings.Index(text, `"task_id": {`)
	if format := strings.Index(text[taskID:], `"format"`); format < 0 || format > 200 {
		t.Errorf("format was not written next to the property it belongs to")
	}
}

// An unannotated leaf must stop the run, and must stop it before anything is
// written: a half-projected document is worse than an unprojected one because
// the failure is invisible in the file that was already replaced.
func TestUnannotatedLeafFailsWithoutWriting(t *testing.T) {
	img := testImage()
	// Drop the option from Response.blob.
	img.File[0].MessageType[1].Field[2].Options = nil

	imagePath, openapiDir := scenario(t, img, testSwagger)
	documentPath := filepath.Join(openapiDir, "task", "v1", "query.swagger.json")
	before, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := apply(imagePath, openapiDir); err == nil {
		t.Fatal("expected a failure for the unannotated leaf")
	} else if !strings.Contains(err.Error(), "verify-rest-encoding") {
		t.Errorf("failure does not point at the lint: %v", err)
	}

	after, err := os.ReadFile(documentPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the document was rewritten despite the failure")
	}
}

// UNSPECIFIED is a decision not taken, and reaches OpenAPI the same way an
// absent option does.
func TestUnspecifiedLeafFails(t *testing.T) {
	img := testImage()
	img.File[0].MessageType[1].Field[2].Options = json.RawMessage(
		`{"[shared.v1.rest_bytes_encoding]":"` + protoimage.EncodingUnspecified + `"}`)

	imagePath, openapiDir := scenario(t, img, testSwagger)
	if _, err := apply(imagePath, openapiDir); err == nil {
		t.Fatal("expected a failure for the UNSPECIFIED leaf")
	}
}

// A definition naming a message the image does not declare means the
// generator's naming strategy drifted from openapi_naming_strategy=fqn. Passing
// over it silently would leave real bytes leaves unprojected, so it fails.
func TestUnknownDefinitionFails(t *testing.T) {
	swagger := strings.Replace(testSwagger, `"task.v1.Page"`, `"task.v1.NoSuchMessage"`, 1)
	imagePath, openapiDir := scenario(t, testImage(), swagger)
	if _, err := apply(imagePath, openapiDir); err == nil {
		t.Fatal("expected a failure for the unresolvable definition")
	} else if !strings.Contains(err.Error(), "NoSuchMessage") {
		t.Errorf("failure does not name the definition: %v", err)
	}
}

// Enums share the definitions map with messages and have nothing to project.
func TestEnumDefinitionIgnored(t *testing.T) {
	imagePath, openapiDir := scenario(t, testImage(), testSwagger)
	if _, err := apply(imagePath, openapiDir); err != nil {
		t.Fatalf("enum definition was treated as a message: %v", err)
	}
	if _, ok := readDocument(t, openapiDir)["definitions"].(map[string]any)["task.v1.Duty"]; !ok {
		t.Error("the enum definition was dropped")
	}
}

// An operation with no descriptor binding means the path key normalisation is
// wrong, which would silently leave every path parameter of that operation
// unprojected.
func TestUnboundOperationFails(t *testing.T) {
	swagger := strings.Replace(testSwagger, `"/v1/task/{task_id}"`, `"/v1/task/{task_id}/extra"`, 1)
	imagePath, openapiDir := scenario(t, testImage(), swagger)
	if _, err := apply(imagePath, openapiDir); err == nil {
		t.Fatal("expected a failure for the unbound operation")
	} else if !strings.Contains(err.Error(), "google.api.http") {
		t.Errorf("failure does not name the missing binding: %v", err)
	}
}

// A path item may carry `parameters` and `$ref` beside its operations. Reading
// those as verbs would fail the run with a binding error about a key that was
// never an operation - a confusing hard stop on a document that is correct.
func TestNonOperationPathItemKeysAreSkipped(t *testing.T) {
	swagger := strings.Replace(testSwagger,
		`      "get": {`,
		`      "parameters": [{"name": "trace", "in": "query", "type": "string"}],
      "get": {`, 1)
	imagePath, openapiDir := scenario(t, testImage(), swagger)
	if _, err := apply(imagePath, openapiDir); err != nil {
		t.Fatalf("a path-item level parameters key was read as a verb: %v", err)
	}
	operation := dig(t, readDocument(t, openapiDir), "paths", "/v1/task/{task_id}", "get")
	parameters, _ := operation["parameters"].([]any)
	if len(parameters) != 2 {
		t.Fatalf("the operation's own parameters were disturbed: %v", operation["parameters"])
	}
	wantHash32(t, parameters[0].(map[string]any), "task_id parameter")
}

// A bytes map value is rendered inline as additionalProperties, so no $ref
// reaches it and the projection cannot rewrite it. verify-rest-encoding forbids
// these; this fails too, so the published document never depends on the lint
// having run to avoid describing an encoding nobody decided.
func TestBytesMapValueFails(t *testing.T) {
	img := testImage()
	response := &img.File[0].MessageType[1]
	response.Field = append(response.Field, protoimage.Field{
		Name: "blobs", Number: 4, Label: protoimage.LabelRepeated,
		Type: protoimage.TypeMessage, TypeName: ".task.v1.Response.BlobsEntry",
	})
	response.NestedType = []protoimage.Message{{
		Name:    "BlobsEntry",
		Options: &protoimage.MessageOptions{MapEntry: true},
		Field: []protoimage.Field{
			{Name: "key", Number: 1, Type: "TYPE_STRING"},
			{Name: "value", Number: 2, Type: protoimage.TypeBytes},
		},
	}}
	swagger := strings.Replace(testSwagger,
		`        "blob": {"type": "string", "format": "byte"}`,
		`        "blob": {"type": "string", "format": "byte"},
        "blobs": {"type": "object", "additionalProperties": {"type": "string", "format": "byte"}}`, 1)

	imagePath, openapiDir := scenario(t, img, swagger)
	if _, err := apply(imagePath, openapiDir); err == nil {
		t.Fatal("expected a failure for the bytes map value")
	} else if !strings.Contains(err.Error(), "blobs") {
		t.Errorf("failure does not name the map field: %v", err)
	}
}

func TestMissingOpenAPIDirectoryFails(t *testing.T) {
	imagePath, _ := scenario(t, testImage(), testSwagger)
	if _, err := apply(imagePath, filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected a failure for the missing directory")
	}
}
