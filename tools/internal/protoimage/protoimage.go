// Package protoimage reads the JSON descriptor image buf produces and exposes
// the parts of it the REST bytes encoding contract is defined in terms of.
//
//	buf build -o build/image.json
//
// Two commands depend on this: verify-rest-encoding lints the annotations, and
// apply-rest-encoding projects them into the generated OpenAPI documents. They
// share this package rather than each parsing the image, because the contract
// in proto/shared/v1/rest_encoding.proto is that the lint and the
// projection read *the same* option. Two independent readers of one descriptor
// drift, and the drift is silent in the worst direction: the lint passes while
// the published schema describes an encoding no server produces.
//
// Reading buf's JSON rather than a generated Go descriptor keeps this module
// dependency-free, and keeps the tools off the code path they check.
package protoimage

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// The three values of shared.v1.RESTBytesEncoding, as buf renders enum
// values of a custom option in JSON.
const (
	EncodingUnspecified = "REST_BYTES_ENCODING_UNSPECIFIED"
	EncodingHash32      = "REST_BYTES_ENCODING_HASH32_LOWER_HEX"
	EncodingBase64      = "REST_BYTES_ENCODING_PROTOJSON_BASE64"
)

// Field type and label constants, as they appear in the JSON image.
const (
	TypeBytes     = "TYPE_BYTES"
	TypeMessage   = "TYPE_MESSAGE"
	TypeGroup     = "TYPE_GROUP"
	LabelRepeated = "LABEL_REPEATED"
)

const (
	restEncodingExtension = "[shared.v1.rest_bytes_encoding]"
	httpRuleExtension     = "[google.api.http]"
)

// ownedPackagePrefixes scope the contract to the packages this repository
// declares. A bytes field inside google.protobuf or a cosmos-sdk type is
// reachable from REST but is not ours to annotate.
var ownedPackagePrefixes = map[string]struct{}{
	"bus": {}, "hub": {}, "nexus": {}, "shared": {}, "task": {},
}

// Owned reports whether a fully qualified type name belongs to this repository.
// The name may carry protobuf's leading dot.
func Owned(typeName string) bool {
	name := strings.TrimPrefix(typeName, ".")
	prefix, _, _ := strings.Cut(name, ".")
	_, ok := ownedPackagePrefixes[prefix]
	return ok
}

// KnownEncoding reports whether value is one of the three declared enum values.
// An unrecognised string means the image was built against a newer
// rest_encoding.proto than this tool knows about, which is a failure rather
// than something to pass through.
func KnownEncoding(value string) bool {
	return value == EncodingUnspecified || value == EncodingHash32 || value == EncodingBase64
}

type Image struct {
	File []File `json:"file"`
}

type File struct {
	Name        string    `json:"name"`
	Package     string    `json:"package"`
	Dependency  []string  `json:"dependency"`
	MessageType []Message `json:"messageType"`
	EnumType    []Enum    `json:"enumType"`
	Service     []Service `json:"service"`
}

type Message struct {
	Name       string          `json:"name"`
	Field      []Field         `json:"field"`
	NestedType []Message       `json:"nestedType"`
	EnumType   []Enum          `json:"enumType"`
	Options    *MessageOptions `json:"options"`
}

// Enum is indexed by name only. Nothing in the REST bytes contract depends on
// an enum's values, but a generated OpenAPI document lists enums alongside
// messages in its definitions, so a consumer has to be able to tell an enum
// from a message it failed to resolve.
type Enum struct {
	Name string `json:"name"`
}

type MessageOptions struct {
	MapEntry  bool   `json:"mapEntry"`
	AminoName string `json:"[amino.name]"`
}

// AminoName returns the stable legacy Amino type name carried by the message
// descriptor. An empty value means the option is absent.
func (m Message) AminoName() string {
	if m.Options == nil {
		return ""
	}
	return m.Options.AminoName
}

type Field struct {
	Name     string          `json:"name"`
	Number   int             `json:"number"`
	Label    string          `json:"label"`
	Type     string          `json:"type"`
	TypeName string          `json:"typeName"`
	Options  json.RawMessage `json:"options"`
}

// Encoding returns the declared REST encoding and whether the option is present
// at all. Absent and UNSPECIFIED are different states here and the callers
// distinguish them: absent means nobody wrote it down, UNSPECIFIED means
// somebody wrote down that they had not decided. Both fail the lint; only the
// caller can phrase the difference.
func (f Field) Encoding() (string, bool) {
	raw, ok := extension(f.Options, restEncodingExtension)
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// Repeated reports whether the field is a list. Map fields are also repeated;
// callers that care distinguish them with Index.MapEntry.
func (f Field) Repeated() bool { return f.Label == LabelRepeated }

type Service struct {
	Name   string   `json:"name"`
	Method []Method `json:"method"`
}

type Method struct {
	Name       string          `json:"name"`
	InputType  string          `json:"inputType"`
	OutputType string          `json:"outputType"`
	Options    json.RawMessage `json:"options"`
}

// HTTPRule is the subset of google.api.HttpRule that binds a path. Only the
// path templates and verbs matter here; nothing routes anything.
type HTTPRule struct {
	Get               string      `json:"get"`
	Put               string      `json:"put"`
	Post              string      `json:"post"`
	Delete            string      `json:"delete"`
	Patch             string      `json:"patch"`
	Body              string      `json:"body"`
	Custom            *CustomRule `json:"custom"`
	AdditionalBinding []HTTPRule  `json:"additionalBindings"`
}

type CustomRule struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

// Binding is one verb/path pair. OpenAPI documents are keyed by exactly this
// pair, so the projection uses it to find the operation a method generated.
type Binding struct {
	Method string // lower-case HTTP verb, as OpenAPI keys operations
	Path   string
}

// Bindings returns every verb/path pair this rule and its additional bindings
// bind, in declaration order.
func (r HTTPRule) Bindings() []Binding {
	var out []Binding
	for _, candidate := range []Binding{
		{"get", r.Get}, {"put", r.Put}, {"post", r.Post},
		{"delete", r.Delete}, {"patch", r.Patch},
	} {
		if candidate.Path != "" {
			out = append(out, candidate)
		}
	}
	if r.Custom != nil && r.Custom.Path != "" {
		out = append(out, Binding{strings.ToLower(r.Custom.Kind), r.Custom.Path})
	}
	for _, additional := range r.AdditionalBinding {
		out = append(out, additional.Bindings()...)
	}
	return out
}

// Paths returns just the path templates, for callers that do not care which
// verb reached them.
func (r HTTPRule) Paths() []string {
	bindings := r.Bindings()
	out := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		out = append(out, binding.Path)
	}
	return out
}

func (m Method) HTTPRule() (HTTPRule, bool) {
	raw, ok := extension(m.Options, httpRuleExtension)
	if !ok {
		return HTTPRule{}, false
	}
	var rule HTTPRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		return HTTPRule{}, false
	}
	return rule, true
}

func extension(options json.RawMessage, name string) (json.RawMessage, bool) {
	if len(options) == 0 {
		return nil, false
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(options, &decoded); err != nil {
		return nil, false
	}
	raw, ok := decoded[name]
	return raw, ok
}

// pathVariablePattern captures the field path of one `{var}` or `{var=pattern}`
// segment of an HTTP path template.
var pathVariablePattern = regexp.MustCompile(`\{([^{}=]+)(?:=[^{}]*)?\}`)

// PathVariables collects the field paths every binding of a rule puts in its
// URL. `{a.b=*}` and `{a.b}` both bind a.b.
func PathVariables(rule HTTPRule) map[string]struct{} {
	out := map[string]struct{}{}
	for _, path := range rule.Paths() {
		for _, match := range pathVariablePattern.FindAllStringSubmatch(path, -1) {
			out[strings.TrimSpace(match[1])] = struct{}{}
		}
	}
	return out
}

// Load reads and parses a buf JSON descriptor image.
func Load(path string) (*Image, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image: %w", err)
	}
	var parsed Image
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse image: %w", err)
	}
	return &parsed, nil
}

// Index resolves the fully qualified type names that field.typeName refers to.
type Index struct {
	messages map[string]Message
	enums    map[string]struct{}
}

// NewIndex records every message and nested type in the image under its fully
// qualified name, with protobuf's leading dot.
func NewIndex(img *Image) *Index {
	index := &Index{messages: map[string]Message{}, enums: map[string]struct{}{}}
	for _, file := range img.File {
		prefix := "." + file.Package
		for _, message := range file.MessageType {
			index.add(prefix+"."+message.Name, message)
		}
		for _, enum := range file.EnumType {
			index.enums[prefix+"."+enum.Name] = struct{}{}
		}
	}
	return index
}

func (x *Index) add(name string, message Message) {
	x.messages[name] = message
	for _, nested := range message.NestedType {
		x.add(name+"."+nested.Name, nested)
	}
	for _, enum := range message.EnumType {
		x.enums[name+"."+enum.Name] = struct{}{}
	}
}

// IsEnum reports whether a fully qualified name is an enum declared in the
// image.
func (x *Index) IsEnum(typeName string) bool {
	_, ok := x.enums[typeName]
	return ok
}

// Message looks up a fully qualified type name.
func (x *Index) Message(typeName string) (Message, bool) {
	message, ok := x.messages[typeName]
	return message, ok
}

// MapEntry reports whether a field is a protobuf map, returning its synthetic
// entry message. A map is a repeated field whose message type is a map entry.
func (x *Index) MapEntry(field Field) (Message, bool) {
	if field.Label != LabelRepeated || field.Type != TypeMessage {
		return Message{}, false
	}
	entry, ok := x.messages[field.TypeName]
	if !ok || entry.Options == nil || !entry.Options.MapEntry || len(entry.Field) != 2 {
		return Message{}, false
	}
	return entry, true
}

// Leaf is one bytes field reached by walking a message closure, named by the
// message that declares it and by the dotted field path from the closure root.
type Leaf struct {
	Owner string // fully qualified declaring message, no leading dot
	Field Field
	Path  string // dotted field path from the root, as URL templates name it
}

// WalkBytes visits every bytes leaf reachable from root, and reports every map
// with a bytes key or value it passes through. The walk stops at types this
// repository does not own, and at types it has already visited, so a recursive
// message terminates.
//
// visitMap is called for each map field whose entry has a bytes part; it may be
// nil. Message-valued maps are still descended into.
func (x *Index) WalkBytes(root string, visitLeaf func(Leaf), visitMap func(owner string, field Field, entry Message)) {
	seen := map[string]struct{}{}

	var walk func(typeName, fieldPath string)
	walk = func(typeName, fieldPath string) {
		if _, done := seen[typeName]; done {
			return
		}
		seen[typeName] = struct{}{}
		message, ok := x.messages[typeName]
		if !ok || !Owned(typeName) {
			return
		}
		owner := strings.TrimPrefix(typeName, ".")
		for _, field := range message.Field {
			path := field.Name
			if fieldPath != "" {
				path = fieldPath + "." + field.Name
			}
			if entry, isMap := x.MapEntry(field); isMap {
				if visitMap != nil {
					for _, part := range entry.Field {
						if part.Type == TypeBytes {
							visitMap(owner, field, entry)
							break
						}
					}
				}
				// A bytes map is rejected elsewhere; a message-valued map still
				// has to have its value closure walked.
				if value := entry.Field[1]; value.Type == TypeMessage || value.Type == TypeGroup {
					walk(value.TypeName, path)
				}
				continue
			}
			switch field.Type {
			case TypeBytes:
				if visitLeaf != nil {
					visitLeaf(Leaf{Owner: owner, Field: field, Path: path})
				}
			case TypeMessage, TypeGroup:
				walk(field.TypeName, path)
			}
		}
	}
	walk(root, "")
}
