// Command apply-rest-encoding projects the REST bytes encoding contract into
// the generated OpenAPI documents.
//
// the API contract fixes the projection:
//
//	HASH32_LOWER_HEX -> {type:string, format:trueopen-hash32,
//	                     pattern:^[0-9a-f]{64}$, minLength:64, maxLength:64}
//	PROTOJSON_BASE64 -> {type:string, format:byte}
//
//
// protoc-gen-openapiv2 knows nothing about shared.v1.rest_bytes_encoding,
// so it renders every bytes field as `{type:string, format:byte}` - including
// the Hash32 path variables that REST carries as 64 lowercase hex. Published
// unaltered, the document would tell every client to Base64 a value the server
// only accepts as hex. This step rewrites those nodes from the descriptor.
//
//	buf build -o build/image.json
//	buf generate --template gen/openapi/buf.gen.yaml ...
//	apply-rest-encoding -image build/image.json -openapi build/gen/openapi
//
// It shares the descriptor reader with verify-rest-encoding (tools/internal/
// protoimage) so the lint and the projection cannot disagree about what an
// annotation says. Run the lint first: this command assumes every public bytes
// leaf is annotated, and reports the ones that are not rather than guessing.
//
// The document is rewritten in place through an order-preserving JSON model, so
// the diff shows the schema nodes that changed and nothing else.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

// The §1.1a projection constants.
const (
	hash32Format  = "trueopen-hash32"
	hash32Pattern = "^[0-9a-f]{64}$"
	hash32Length  = 64
	base64Format  = "byte"
)

// base64Note is the alphabet/padding statement §1.1a requires the projection to
// carry. One sentence covers both directions because a definition is shared by
// requests and responses; splitting the definition per direction to phrase them
// separately would double the schema for no reader's benefit.
const base64Note = "REST input accepts the standard or URL-safe Base64 alphabet, " +
	"padded or unpadded; REST output is always the canonical padded standard-alphabet form."

// pathTemplateArgument strips the `=pattern` half of a `{var=pattern}` segment,
// which grpc-gateway drops when it writes the OpenAPI path key.
var pathTemplateArgument = regexp.MustCompile(`\{([^{}=]+)=[^{}]*\}`)

// operationKeys is the Swagger 2.0 path item operation set. The remaining path
// item keys - `parameters` and `$ref` - are not operations and must not be
// looked up as HTTP verbs.
var operationKeys = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true,
}

func main() {
	imagePath := flag.String("image", "build/image.json", "buf JSON descriptor image")
	openapiDir := flag.String("openapi", "build/gen/openapi", "directory of generated *.swagger.json documents")
	flag.Parse()

	changed, err := apply(*imagePath, *openapiDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("projected rest_bytes_encoding onto %d OpenAPI schema node(s)\n", changed)
}

type projector struct {
	index    *protoimage.Index
	bindings map[protoimage.Binding]string // verb+path -> request message FQN
	problems []string
}

func apply(imagePath, openapiDir string) (int, error) {
	img, err := protoimage.Load(imagePath)
	if err != nil {
		return 0, err
	}

	project := &projector{
		index:    protoimage.NewIndex(img),
		bindings: map[protoimage.Binding]string{},
	}
	for _, file := range img.File {
		for _, service := range file.Service {
			for _, method := range service.Method {
				rule, ok := method.HTTPRule()
				if !ok {
					continue
				}
				for _, binding := range rule.Bindings() {
					binding.Path = normalizePath(binding.Path)
					project.bindings[binding] = method.InputType
				}
			}
		}
	}

	documents, err := swaggerDocuments(openapiDir)
	if err != nil {
		return 0, err
	}
	if len(documents) == 0 {
		return 0, fmt.Errorf("no *.swagger.json under %s; run buf generate first", openapiDir)
	}

	// Every document is projected in memory first and nothing is written until
	// all of them succeed. A partial rewrite is worse than no rewrite: it
	// publishes a half-projected document, and the failure that stopped the run
	// is invisible in the file that was already written.
	type pending struct {
		path string
		root *protoimage.Node
	}
	var writes []pending
	changed := 0
	for _, path := range documents {
		root, count, err := project.document(path)
		if err != nil {
			return 0, err
		}
		changed += count
		if count > 0 {
			writes = append(writes, pending{path, root})
		}
	}

	if len(project.problems) > 0 {
		sort.Strings(project.problems)
		return 0, fmt.Errorf("cannot project rest_bytes_encoding:\n  %s",
			strings.Join(project.problems, "\n  "))
	}

	for _, write := range writes {
		encoded, err := protoimage.MarshalIndentJSON(write.root)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", write.path, err)
		}
		if err := os.WriteFile(write.path, encoded, 0o644); err != nil {
			return 0, err
		}
	}
	return changed, nil
}

func swaggerDocuments(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".swagger.json") {
			out = append(out, path)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("openapi directory %s does not exist; run buf generate first", root)
	}
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func (p *projector) reportf(format string, args ...any) {
	p.problems = append(p.problems, fmt.Sprintf(format, args...))
}

// normalizePath rewrites `{var=pattern}` to `{var}`, which is how grpc-gateway
// writes the key of the generated path item.
func normalizePath(path string) string {
	return pathTemplateArgument.ReplaceAllString(path, "{$1}")
}

// document projects one file and returns the edited tree without writing it.
func (p *projector) document(path string) (*protoimage.Node, int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	root, err := protoimage.ParseJSON(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}

	changed := p.definitions(path, root.Get("definitions"))
	changed += p.paths(path, root.Get("paths"))
	return root, changed, nil
}

// definitions rewrites the bytes properties of every definition that names a
// message this repository owns. openapi_naming_strategy=fqn makes the
// definition key the protobuf fully qualified name and json_names_for_fields=
// false makes the property key the protobuf field name, so the mapping is
// exact - no name matching, no heuristics.
func (p *projector) definitions(document string, definitions *protoimage.Node) int {
	if definitions == nil {
		return 0
	}
	changed := 0
	for i, name := range definitions.Keys {
		if !protoimage.Owned(name) {
			continue
		}
		if p.index.IsEnum("." + name) {
			// A generated document lists enums in definitions too. They have no
			// bytes leaf and nothing to project.
			continue
		}
		message, ok := p.index.Message("." + name)
		if !ok {
			// A definition naming a trueopen* type that the image does not declare
			// means the naming strategy changed under this tool; silently
			// skipping it would leave bytes fields unprojected.
			p.reportf("%s: definition %s has no message in the descriptor image", document, name)
			continue
		}
		fields := map[string]protoimage.Field{}
		for _, field := range message.Field {
			fields[field.Name] = field
		}
		properties := definitions.Values[i].Get("properties")
		if properties == nil {
			continue
		}
		for j, property := range properties.Keys {
			field, ok := fields[property]
			if !ok {
				p.reportf("%s: %s.%s has no field in the descriptor image; "+
					"the generator's field naming no longer matches the descriptor",
					document, name, property)
				continue
			}
			// A map is checked before the bytes test, not after it: a map field
			// is TYPE_MESSAGE, so a test ordered the other way could never see
			// one, and a bytes map value - rendered as an inline
			// additionalProperties schema no `$ref` reaches - would be skipped
			// in silence. verify-rest-encoding forbids these outright; failing
			// here too means the projection does not depend on the lint having
			// run to avoid publishing an unprojected encoding.
			if entry, isMap := p.index.MapEntry(field); isMap {
				for _, part := range entry.Field {
					if part.Type == protoimage.TypeBytes {
						p.reportf("%s: %s.%s is a map with a bytes %s, which V1 public "+
							"REST forbids; run verify-rest-encoding",
							document, name, property, part.Name)
						break
					}
				}
				continue
			}
			if field.Type != protoimage.TypeBytes {
				continue
			}
			encoding, present := field.Encoding()
			if !present || encoding == protoimage.EncodingUnspecified {
				p.reportf("%s: %s.%s reaches OpenAPI without a decided rest_bytes_encoding; "+
					"run verify-rest-encoding", document, name, property)
				continue
			}
			if p.applySchema(document, properties.Values[j], encoding, name+"."+property) {
				changed++
			}
		}
	}
	return changed
}

// paths rewrites the inline schemas of path and query parameters. Swagger 2.0
// spells non-body parameters inline rather than as a $ref, so the definition
// pass above does not reach them - and path parameters are exactly where a
// wrong encoding hurts most, because a Base64 digest in a URL is not a digest.
func (p *projector) paths(document string, paths *protoimage.Node) int {
	if paths == nil {
		return 0
	}
	changed := 0
	for i, urlPath := range paths.Keys {
		item := paths.Values[i]
		for j, verb := range item.Keys {
			if !operationKeys[strings.ToLower(verb)] {
				// A path item may also carry `parameters` and `$ref`. Treating
				// those as verbs would fail the run with a binding error about a
				// key that was never an operation.
				continue
			}
			request, ok := p.bindings[protoimage.Binding{Method: strings.ToLower(verb), Path: urlPath}]
			if !ok {
				p.reportf("%s: %s %s has no google.api.http binding in the descriptor image",
					document, verb, urlPath)
				continue
			}
			parameters := item.Values[j].Get("parameters")
			if parameters == nil {
				continue
			}
			for _, parameter := range parameters.Elems {
				changed += p.parameter(document, request, parameter)
			}
		}
	}
	return changed
}

func (p *projector) parameter(document, request string, parameter *protoimage.Node) int {
	name, ok := parameter.Get("name").String()
	if !ok {
		return 0
	}
	location, _ := parameter.Get("in").String()
	if location == "body" {
		// A body parameter carries a $ref into definitions, which the
		// definition pass already rewrote.
		return 0
	}
	field, ok := p.resolve(request, name)
	if !ok {
		p.reportf("%s: parameter %q of %s resolves to no field of %s",
			document, name, location, strings.TrimPrefix(request, "."))
		return 0
	}
	if field.Type != protoimage.TypeBytes {
		return 0
	}
	encoding, present := field.Encoding()
	if !present || encoding == protoimage.EncodingUnspecified {
		p.reportf("%s: parameter %q of %s reaches OpenAPI without a decided rest_bytes_encoding; "+
			"run verify-rest-encoding", document, name, strings.TrimPrefix(request, "."))
		return 0
	}
	if p.applySchema(document, parameter, encoding, strings.TrimPrefix(request, ".")+" parameter "+name) {
		return 1
	}
	return 0
}

// resolve walks a dotted field path from a root message, the way an HTTP path
// template and grpc-gateway's query parameter names name a nested field.
func (p *projector) resolve(root, path string) (protoimage.Field, bool) {
	current := root
	segments := strings.Split(path, ".")
	for i, segment := range segments {
		message, ok := p.index.Message(current)
		if !ok {
			return protoimage.Field{}, false
		}
		var found *protoimage.Field
		for k := range message.Field {
			if message.Field[k].Name == segment {
				found = &message.Field[k]
				break
			}
		}
		if found == nil {
			return protoimage.Field{}, false
		}
		if i == len(segments)-1 {
			return *found, true
		}
		if found.Type != protoimage.TypeMessage && found.Type != protoimage.TypeGroup {
			return protoimage.Field{}, false
		}
		current = found.TypeName
	}
	return protoimage.Field{}, false
}

// applySchema rewrites one schema or inline parameter node. A repeated field is
// rewrite targets the item schema in that case. Keys already present are
// replaced in place; only genuinely new keys are appended.
func (p *projector) applySchema(document string, node *protoimage.Node, encoding, where string) bool {
	if node == nil {
		return false
	}
	target := node
	if kind, _ := node.Get("type").String(); kind == "array" {
		target = node.Get("items")
		if target == nil {
			p.reportf("%s: %s is an array with no item schema", document, where)
			return false
		}
	}

	before, _ := protoimage.MarshalIndentJSON(target)

	switch encoding {
	case protoimage.EncodingHash32:
		target.Set("type", protoimage.StringNode("string"))
		target.Set("format", protoimage.StringNode(hash32Format))
		target.Set("pattern", protoimage.StringNode(hash32Pattern))
		target.Set("minLength", protoimage.IntNode(hash32Length))
		target.Set("maxLength", protoimage.IntNode(hash32Length))
	case protoimage.EncodingBase64:
		target.Set("type", protoimage.StringNode("string"))
		target.Set("format", protoimage.StringNode(base64Format))
		// Clear any Hash32 constraint a previous run left behind, so this
		// command is idempotent in both directions rather than only forwards.
		target.Delete("pattern")
		target.Delete("minLength")
		target.Delete("maxLength")
		appendNote(target, base64Note)
	default:
		p.reportf("%s: %s declares unknown encoding %q", document, where, encoding)
		return false
	}

	after, _ := protoimage.MarshalIndentJSON(target)
	return string(before) != string(after)
}

// appendNote adds the alphabet/padding sentence once, keeping whatever
// description the proto comment already produced.
func appendNote(target *protoimage.Node, note string) {
	existing, _ := target.Get("description").String()
	if strings.Contains(existing, note) {
		return
	}
	if existing == "" {
		target.Set("description", protoimage.StringNode(note))
		return
	}
	target.Set("description", protoimage.StringNode(existing+"\n\n"+note))
}
