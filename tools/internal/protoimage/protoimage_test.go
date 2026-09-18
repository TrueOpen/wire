package protoimage

import (
	"encoding/json"
	"strings"
	"testing"
)

// A round-trip that changes nothing must return the document byte for byte.
// This is the property the whole ordered model exists for: if re-encoding
// perturbs an untouched document, every generated OpenAPI file would show a
// whole-file diff and the schema changes that matter would be unreviewable.
func TestRoundTripIsByteExact(t *testing.T) {
	cases := []string{
		`{"b":1,"a":2,"c":{"z":[1,2,{"y":null}],"m":"x"}}`,
		`{"unicode":"Chinese é \"quoted\" \\ backslash","tab":"a\tb\nc"}`,
		`{"big":12345678901234567890,"float":1.7976931348623157e+308,"neg":-0}`,
		`{"empty_object":{},"empty_array":[],"nulls":[null,null]}`,
		`[]`,
		`{"deep":{"deep":{"deep":{"deep":[{"k":true},false]}}}}`,
	}
	for _, source := range cases {
		node, err := ParseJSON([]byte(source))
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		encoded, err := node.MarshalJSON()
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		// Compare through a normalising decode as well, so a difference in
		// escaping style is not mistaken for a difference in content.
		var want, got any
		if err := json.Unmarshal([]byte(source), &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("re-encoded %s is not valid JSON: %v", source, err)
		}
		wantEncoded, _ := json.Marshal(want)
		gotEncoded, _ := json.Marshal(got)
		if string(wantEncoded) != string(gotEncoded) {
			t.Errorf("round trip changed content:\n  in  %s\n  out %s", source, encoded)
		}
	}
}

// A large integer must not be routed through float64, which would silently
// round it.
func TestLargeNumbersSurvive(t *testing.T) {
	const source = `{"n":9007199254740993}`
	node, err := ParseJSON([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := node.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "9007199254740993") {
		t.Errorf("integer lost precision: %s", encoded)
	}
}

func TestKeyOrderIsPreservedAcrossEdits(t *testing.T) {
	node, err := ParseJSON([]byte(`{"type":"string","format":"byte","description":"d"}`))
	if err != nil {
		t.Fatal(err)
	}
	// Replacing an existing key must not move it; a new key goes to the end.
	node.Set("format", StringNode("trueopen-hash32"))
	node.Set("pattern", StringNode("^[0-9a-f]{64}$"))
	node.Set("minLength", IntNode(64))

	encoded, err := node.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"string","format":"trueopen-hash32","description":"d",` +
		`"pattern":"^[0-9a-f]{64}$","minLength":64}`
	if string(encoded) != want {
		t.Errorf("got  %s\nwant %s", encoded, want)
	}
}

func TestDeleteAndGet(t *testing.T) {
	node, err := ParseJSON([]byte(`{"a":1,"b":2,"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	node.Delete("b")
	node.Delete("absent")
	encoded, _ := node.MarshalJSON()
	if string(encoded) != `{"a":1,"c":3}` {
		t.Errorf("got %s", encoded)
	}
	if node.Get("b") != nil {
		t.Error("deleted key is still readable")
	}
	if value, ok := node.Get("a").String(); ok || value != "" {
		t.Errorf("a number read as a string: %q %v", value, ok)
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

// bytesField and the image below mirror the shapes the real descriptor has.
func bytesField(name, encoding string, repeated bool) Field {
	field := Field{Name: name, Type: TypeBytes, Label: "LABEL_OPTIONAL"}
	if repeated {
		field.Label = LabelRepeated
	}
	if encoding != "" {
		field.Options = json.RawMessage(`{"` + restEncodingExtension + `":"` + encoding + `"}`)
	}
	return field
}

func TestEncodingReadsTheOption(t *testing.T) {
	if value, ok := bytesField("a", EncodingHash32, false).Encoding(); !ok || value != EncodingHash32 {
		t.Errorf("got %q %v", value, ok)
	}
	if _, ok := bytesField("a", "", false).Encoding(); ok {
		t.Error("an absent option was reported as present")
	}
	// An option block that carries other extensions but not this one.
	other := Field{Name: "a", Type: TypeBytes, Options: json.RawMessage(`{"deprecated":true}`)}
	if _, ok := other.Encoding(); ok {
		t.Error("an unrelated option was read as an encoding")
	}
}

func TestOwnedAndKnownEncoding(t *testing.T) {
	for _, name := range []string{".task.v1.X", "hub.v1.Y", ".shared.v1.Z"} {
		if !Owned(name) {
			t.Errorf("%s should be owned", name)
		}
	}
	for _, name := range []string{".google.protobuf.Any", "cosmos.base.v1beta1.Coin"} {
		if Owned(name) {
			t.Errorf("%s should not be owned", name)
		}
	}
	if KnownEncoding("REST_BYTES_ENCODING_HEX") {
		t.Error("an unknown enum value was accepted")
	}
	if !KnownEncoding(EncodingBase64) {
		t.Error("a declared enum value was rejected")
	}
}

func TestBindingsCoverEveryVerbAndAdditionalBinding(t *testing.T) {
	rule := HTTPRule{
		Get:  "/v1/a/{id}",
		Post: "/v1/a",
		AdditionalBinding: []HTTPRule{
			{Get: "/v1/legacy/{id=*}"},
		},
		Custom: &CustomRule{Kind: "OPTIONS", Path: "/v1/a"},
	}
	got := rule.Bindings()
	if len(got) != 4 {
		t.Fatalf("got %d bindings: %v", len(got), got)
	}
	if got[0] != (Binding{"get", "/v1/a/{id}"}) || got[1] != (Binding{"post", "/v1/a"}) {
		t.Errorf("verbs out of order: %v", got)
	}
	if got[2].Method != "options" {
		t.Errorf("custom verb not lower-cased: %v", got[2])
	}

	variables := PathVariables(rule)
	if _, ok := variables["id"]; !ok || len(variables) != 1 {
		t.Errorf("path variables %v", variables)
	}
}

func TestPathVariablesReadsNestedPaths(t *testing.T) {
	variables := PathVariables(HTTPRule{Get: "/v1/{a.b.c}/x/{d=**}"})
	for _, want := range []string{"a.b.c", "d"} {
		if _, ok := variables[want]; !ok {
			t.Errorf("missing %q in %v", want, variables)
		}
	}
}

func walkImage() *Image {
	return &Image{File: []File{{
		Package: "task.v1",
		MessageType: []Message{
			{Name: "Root", Field: []Field{
				bytesField("id", EncodingHash32, false),
				{Name: "child", Type: TypeMessage, TypeName: ".task.v1.Child"},
				{Name: "foreign", Type: TypeMessage, TypeName: ".google.protobuf.Any"},
				{Name: "loop", Type: TypeMessage, TypeName: ".task.v1.Root"},
				{Name: "blobs", Label: LabelRepeated, Type: TypeMessage,
					TypeName: ".task.v1.Root.BlobsEntry"},
			}, NestedType: []Message{{
				Name:    "BlobsEntry",
				Options: &MessageOptions{MapEntry: true},
				Field: []Field{
					{Name: "key", Type: "TYPE_STRING"},
					{Name: "value", Type: TypeBytes},
				},
			}}},
			{Name: "Child", Field: []Field{bytesField("digest", EncodingBase64, true)}},
		},
		EnumType: []Enum{{Name: "Duty"}},
	}, {
		Package: "google.protobuf",
		MessageType: []Message{{Name: "Any", Field: []Field{
			bytesField("value", "", false),
		}}},
	}}}
}

func TestWalkBytesStopsAtBoundariesAndCycles(t *testing.T) {
	index := NewIndex(walkImage())

	var leaves []string
	var maps []string
	index.WalkBytes(".task.v1.Root",
		func(leaf Leaf) { leaves = append(leaves, leaf.Owner+"."+leaf.Field.Name+"@"+leaf.Path) },
		func(owner string, field Field, entry Message) { maps = append(maps, owner+"."+field.Name) })

	want := map[string]bool{
		"task.v1.Root.id@id":                true,
		"task.v1.Child.digest@child.digest": true,
	}
	if len(leaves) != len(want) {
		t.Fatalf("visited %v, want %v", leaves, want)
	}
	for _, leaf := range leaves {
		if !want[leaf] {
			t.Errorf("unexpected leaf %s", leaf)
		}
	}
	// google.protobuf.Any.value is reachable but not ours, so it is not visited.
	for _, leaf := range leaves {
		if strings.Contains(leaf, "google.protobuf") {
			t.Errorf("walked into a foreign package: %s", leaf)
		}
	}
	if len(maps) != 1 || maps[0] != "task.v1.Root.blobs" {
		t.Errorf("bytes map not reported once: %v", maps)
	}
}

func TestIndexResolvesNestedTypesAndEnums(t *testing.T) {
	index := NewIndex(walkImage())
	if _, ok := index.Message(".task.v1.Root.BlobsEntry"); !ok {
		t.Error("nested type not indexed")
	}
	if !index.IsEnum(".task.v1.Duty") {
		t.Error("enum not indexed")
	}
	if index.IsEnum(".task.v1.Root") {
		t.Error("a message was reported as an enum")
	}
	root, _ := index.Message(".task.v1.Root")
	if _, isMap := index.MapEntry(root.Field[4]); !isMap {
		t.Error("map field not recognised")
	}
	if _, isMap := index.MapEntry(root.Field[1]); isMap {
		t.Error("a plain message field was read as a map")
	}
}
