package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

// A lint that only ever passes is indistinguishable from no lint at all, so
// every rule below is exercised by an image that violates it. The images are
// hand-built rather than compiled from .proto sources on purpose: the point is
// to check this tool's reading of a descriptor, and generating the descriptor
// with the same toolchain the tool trusts would only compare buf against itself.

const (
	base64Encoding = protoimage.EncodingBase64
	hexEncoding    = protoimage.EncodingHash32
)

func bytesField(name string, number int, encoding string) protoimage.Field {
	field := protoimage.Field{Name: name, Number: number, Label: "LABEL_OPTIONAL", Type: protoimage.TypeBytes}
	if encoding != "" {
		field.Options = json.RawMessage(`{"[shared.v1.rest_bytes_encoding]":"` + encoding + `"}`)
	}
	return field
}

func messageField(name string, number int, typeName string) protoimage.Field {
	return protoimage.Field{
		Name: name, Number: number, Label: "LABEL_OPTIONAL",
		Type: protoimage.TypeMessage, TypeName: typeName,
	}
}

// getMethod binds one GET path so path-variable rules can also be exercised.
func getMethod(path string) protoimage.Method {
	return protoimage.Method{
		Name:       "Get",
		InputType:  ".task.v1.Request",
		OutputType: ".task.v1.Response",
		Options:    json.RawMessage(`{"[google.api.http]":{"get":"` + path + `"}}`),
	}
}

func rpcMethod(name, input, output string) protoimage.Method {
	return protoimage.Method{Name: name, InputType: input, OutputType: output}
}

// trueopenImage wraps repo-owned messages in the one file/service shape the tool
// walks, so each test only has to state the messages it cares about.
func trueopenImage(messages ...protoimage.Message) protoimage.Image {
	return protoimage.Image{File: []protoimage.File{{
		Name:        "task/v1/query.proto",
		Package:     "task.v1",
		MessageType: messages,
		Service:     []protoimage.Service{{Name: "Query", Method: []protoimage.Method{getMethod("/v1/thing")}}},
	}}}
}

func runLint(t *testing.T, img protoimage.Image) (int, error) {
	t.Helper()
	encoded, err := json.Marshal(img)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return verify(path)
}

func wantViolation(t *testing.T, img protoimage.Image, fragment string) {
	t.Helper()
	if _, err := runLint(t, img); err == nil {
		t.Fatalf("expected a violation mentioning %q, got none", fragment)
	} else if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("violation %q does not mention %q", err, fragment)
	}
}

func TestAnnotatedClosurePasses(t *testing.T) {
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{
			bytesField("task_id", 1, hexEncoding),
			messageField("filter", 2, ".task.v1.Filter"),
		}},
		protoimage.Message{Name: "Response", Field: []protoimage.Field{
			bytesField("blob", 1, base64Encoding),
		}},
		protoimage.Message{Name: "Filter", Field: []protoimage.Field{
			bytesField("cursor", 1, base64Encoding),
		}},
	)
	count, err := runLint(t, img)
	if err != nil {
		t.Fatalf("clean image rejected: %v", err)
	}
	// Nested closures count too: task_id, blob and Filter.cursor.
	if count != 3 {
		t.Fatalf("checked %d leaves, want 3", count)
	}
}

// Rule 1: the option belongs on bytes and nowhere else. This one is checked
// across the whole image, so it fires even with no HTTP binding in sight.
func TestOptionOnNonBytesFieldFails(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{{
		Name:    "hub/v1/internal.proto",
		Package: "hub.v1",
		MessageType: []protoimage.Message{{Name: "Row", Field: []protoimage.Field{{
			Name: "height", Number: 1, Label: "LABEL_OPTIONAL", Type: "TYPE_UINT64",
			Options: json.RawMessage(`{"[shared.v1.rest_bytes_encoding]":"` + hexEncoding + `"}`),
		}}}},
	}}}
	wantViolation(t, img, "is TYPE_UINT64, not bytes")
}

// Rule 2, the missing half: an unannotated bytes leaf that a public RPC reaches.
func TestUnannotatedPublicBytesFails(t *testing.T) {
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
		protoimage.Message{Name: "Response", Field: []protoimage.Field{bytesField("blob", 1, "")}},
	)
	wantViolation(t, img, "carries no rest_bytes_encoding")
}

func TestUnannotatedPublicMsgBytesFailsWithoutHTTP(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{{
		Name:    "hub/v1/tx.proto",
		Package: "hub.v1",
		MessageType: []protoimage.Message{
			{Name: "Request", Field: []protoimage.Field{bytesField("signature", 1, "")}},
			{Name: "Response"},
		},
		Service: []protoimage.Service{{
			Name: "Msg", Method: []protoimage.Method{
				rpcMethod("Submit", ".hub.v1.Request", ".hub.v1.Response"),
			},
		}},
	}}}
	wantViolation(t, img, "hub.v1.Request.signature")
}

func TestUnannotatedEventStreamBytesFailsWithoutHTTP(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{{
		Name:    "task/v1/task_event.proto",
		Package: "task.v1",
		MessageType: []protoimage.Message{
			{Name: "Request"},
			{Name: "Response", Field: []protoimage.Field{bytesField("block_hash", 1, "")}},
		},
		Service: []protoimage.Service{{
			Name: "TaskEventService", Method: []protoimage.Method{
				rpcMethod("Subscribe", ".task.v1.Request", ".task.v1.Response"),
			},
		}},
	}}}
	wantViolation(t, img, "task.v1.Response.block_hash")
}

func TestUnregisteredServiceIsOutsidePublicClosure(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{{
		Name:    "hub/v1/internal.proto",
		Package: "hub.v1",
		MessageType: []protoimage.Message{
			{Name: "Request", Field: []protoimage.Field{bytesField("raw", 1, "")}},
			{Name: "Response"},
		},
		Service: []protoimage.Service{{
			Name: "InternalAdmin", Method: []protoimage.Method{
				rpcMethod("Read", ".hub.v1.Request", ".hub.v1.Response"),
			},
		}},
	}}}
	if _, err := runLint(t, img); err != nil {
		t.Fatalf("unregistered internal service reported: %v", err)
	}
}

// Rule 2, the undecided half. UNSPECIFIED is not a weaker failure than absence:
// both mean the projection was never chosen.
func TestUnspecifiedPublicBytesFails(t *testing.T) {
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
		protoimage.Message{Name: "Response", Field: []protoimage.Field{
			bytesField("blob", 1, protoimage.EncodingUnspecified),
		}},
	)
	wantViolation(t, img, "declares REST_BYTES_ENCODING_UNSPECIFIED")
}

// A leaf only reachable through a nested message is still public. This is the
// case a field-name allowlist gets wrong.
func TestUnannotatedNestedBytesFails(t *testing.T) {
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
		protoimage.Message{Name: "Response", Field: []protoimage.Field{
			messageField("page", 1, ".task.v1.Page"),
		}},
		protoimage.Message{Name: "Page", Field: []protoimage.Field{bytesField("next_key", 1, "")}},
	)
	wantViolation(t, img, "task.v1.Page.next_key")
}

// Rule 3: V1 has no defined encoding for a map value, so a bytes map may not
// appear in a public closure at all.
func TestBytesMapValueFails(t *testing.T) {
	entry := protoimage.Message{
		Name:    "AttachmentsEntry",
		Options: &protoimage.MessageOptions{MapEntry: true},
		Field: []protoimage.Field{
			{Name: "key", Number: 1, Label: "LABEL_OPTIONAL", Type: "TYPE_STRING"},
			{Name: "value", Number: 2, Label: "LABEL_OPTIONAL", Type: protoimage.TypeBytes},
		},
	}
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
		protoimage.Message{
			Name: "Response",
			Field: []protoimage.Field{{
				Name: "attachments", Number: 1, Label: protoimage.LabelRepeated,
				Type: protoimage.TypeMessage, TypeName: ".task.v1.Response.AttachmentsEntry",
			}},
			NestedType: []protoimage.Message{entry},
		},
	)
	wantViolation(t, img, "has a bytes value")
}

// Rule 4: Base64 never enters a URL path, because the path alphabet and the
// Base64 alphabet do not agree and a percent-encoded digest is not a digest.
func TestBase64BytesInPathFails(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{{
		Name:    "task/v1/query.proto",
		Package: "task.v1",
		MessageType: []protoimage.Message{
			{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, base64Encoding)}},
			{Name: "Response", Field: []protoimage.Field{bytesField("blob", 1, base64Encoding)}},
		},
		Service: []protoimage.Service{{
			Name:   "Query",
			Method: []protoimage.Method{getMethod("/v1/tasks/{task_id}")},
		}},
	}}}
	wantViolation(t, img, "only HASH32_LOWER_HEX may enter a path")
}

// The same path variable with the right encoding is fine, including the
// `{var=pattern}` form the template syntax allows.
func TestHash32InPathPasses(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{{
		Name:    "task/v1/query.proto",
		Package: "task.v1",
		MessageType: []protoimage.Message{
			{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
			{Name: "Response", Field: []protoimage.Field{bytesField("blob", 1, base64Encoding)}},
		},
		Service: []protoimage.Service{{
			Name:   "Query",
			Method: []protoimage.Method{getMethod("/v1/tasks/{task_id=*}")},
		}},
	}}}
	if _, err := runLint(t, img); err != nil {
		t.Fatalf("hash32 path variable rejected: %v", err)
	}
}

// A bytes field inside a dependency is reachable from REST but is not ours to
// annotate. Demanding an option there would make the gate unfixable, so the
// walk stops at the package boundary.
func TestForeignMessageIsExempt(t *testing.T) {
	img := protoimage.Image{File: []protoimage.File{
		{
			Name:    "task/v1/query.proto",
			Package: "task.v1",
			MessageType: []protoimage.Message{
				{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
				{Name: "Response", Field: []protoimage.Field{
					messageField("detail", 1, ".google.protobuf.Any"),
				}},
			},
			Service: []protoimage.Service{{
				Name:   "Query",
				Method: []protoimage.Method{getMethod("/v1/thing")},
			}},
		},
		{
			Name:    "google/protobuf/any.proto",
			Package: "google.protobuf",
			MessageType: []protoimage.Message{{Name: "Any", Field: []protoimage.Field{
				{Name: "type_url", Number: 1, Label: "LABEL_OPTIONAL", Type: "TYPE_STRING"},
				bytesField("value", 2, ""),
			}}},
		},
	}}
	if _, err := runLint(t, img); err != nil {
		t.Fatalf("foreign bytes leaf reported: %v", err)
	}
}

// A message none of the six public services reaches may stay unannotated.
func TestUnreachableMessageIsExempt(t *testing.T) {
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
		protoimage.Message{Name: "Response", Field: []protoimage.Field{bytesField("blob", 1, base64Encoding)}},
		protoimage.Message{Name: "StoreRow", Field: []protoimage.Field{bytesField("raw", 1, "")}},
	)
	if _, err := runLint(t, img); err != nil {
		t.Fatalf("unreachable message reported: %v", err)
	}
}

// Recursive messages must not hang the walk.
func TestRecursiveClosureTerminates(t *testing.T) {
	img := trueopenImage(
		protoimage.Message{Name: "Request", Field: []protoimage.Field{bytesField("task_id", 1, hexEncoding)}},
		protoimage.Message{Name: "Response", Field: []protoimage.Field{
			messageField("node", 1, ".task.v1.Node"),
		}},
		protoimage.Message{Name: "Node", Field: []protoimage.Field{
			bytesField("id", 1, hexEncoding),
			messageField("child", 2, ".task.v1.Node"),
		}},
	)
	if _, err := runLint(t, img); err != nil {
		t.Fatalf("recursive closure rejected: %v", err)
	}
}

// The real image is the case that matters: this asserts the tool is pointed at
// something with content, so a walk that silently reached nothing cannot pass.
func TestRepositoryImageIsFullyAnnotated(t *testing.T) {
	const imagePath = "../../build/image.json"
	if _, err := os.Stat(imagePath); err != nil {
		t.Skip("build/image.json not present; run buf build -o build/image.json")
	}
	count, err := verify(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if count < 300 {
		t.Fatalf("only %d public service bytes leaves checked; the closure walk is not reaching Msg, Query and event schemas", count)
	}
}
