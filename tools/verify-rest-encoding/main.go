// Command verify-rest-encoding is the lint half of the REST bytes encoding
// contract.
//
// proto/shared/v1/rest_encoding.proto declares the option and states the
// rules in prose, but prose does not fail a build. Without this tool the option
// is decoration: a public Msg, Query or event RPC can pull an unannotated
// message into the client-facing descriptor closure and every generated client
// will quietly guess an encoding for its bytes leaves - which is exactly the
// field-name-table behaviour the API contract exists to abolish. The
// guess is invisible until two implementations guess differently about the
// same field.
//
// It reads buf's JSON descriptor image rather than a generated Go descriptor, so
// it stays in step with the rest of this module: no wire tool links against
// generated code, because a tool that shares a code path with the thing it
// checks cannot detect that code path being wrong. The reader lives in
// tools/internal/protoimage, shared with apply-rest-encoding, because §1.1a
// requires the lint and the OpenAPI projection to read the same option.
//
//	buf build -o build/image.json
//	verify-rest-encoding -image build/image.json
//
// Four rules, all from §1.1a:
//
//  1. The option may only sit on a `bytes` field. Anywhere in the image, not
//     just under REST.
//  2. Every bytes leaf reachable from one of the six public Hub/Task services
//     must carry the option with a value other than UNSPECIFIED. Missing and
//     UNSPECIFIED are the same failure: both mean nobody decided.
//  3. No map with a bytes key or value may appear in a public service closure.
//     V1 leaves map-value option semantics undefined, so the schema may not use
//     one yet.
//  4. A bytes field bound to a URL path variable must be HASH32_LOWER_HEX.
//     Base64 bytes never enter a path.
//
// Rules 2-4 apply only to messages this repository owns. A bytes field inside
// google.protobuf or a cosmos-sdk type is reachable from REST but is not ours to
// annotate, and demanding an option there would make the gate unfixable.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

var publicServiceRoots = map[string]struct{}{
	"hub.v1.Msg":               {},
	"hub.v1.Query":             {},
	"hub.v1.HubEventService":   {},
	"task.v1.Msg":              {},
	"task.v1.Query":            {},
	"task.v1.TaskEventService": {},
}

func main() {
	imagePath := flag.String("image", "build/image.json", "buf JSON descriptor image to check")
	flag.Parse()

	count, err := verify(*imagePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("verified %d annotated public service bytes leaf/leaves\n", count)
}

// linter accumulates violations instead of stopping at the first one: a
// contributor who added one public RPC wants the whole closure reported once,
// not one field per run.
type linter struct {
	index    *protoimage.Index
	problems []string
	// checked is keyed by declaring message and field name. One leaf reachable
	// from four RPCs is one annotated leaf, not four, and reporting the
	// visit count instead would overstate the coverage this gate has.
	checked map[string]struct{}
}

func verify(imagePath string) (int, error) {
	img, err := protoimage.Load(imagePath)
	if err != nil {
		return 0, err
	}

	lint := &linter{index: protoimage.NewIndex(img), checked: map[string]struct{}{}}

	// Rule 1 covers the whole image, including messages no HTTP binding reaches.
	for _, file := range img.File {
		for _, message := range file.MessageType {
			lint.checkOptionPlacement(file.Name, file.Package, message)
		}
	}

	for _, file := range img.File {
		for _, service := range file.Service {
			serviceName := file.Package + "." + service.Name
			if _, public := publicServiceRoots[serviceName]; !public {
				continue
			}
			for _, method := range service.Method {
				origin := serviceName + "." + method.Name
				var variables map[string]struct{}
				if rule, ok := method.HTTPRule(); ok {
					variables = protoimage.PathVariables(rule)
				}
				lint.checkClosure(origin, method.InputType, variables)
				lint.checkClosure(origin, method.OutputType, nil)
			}
		}
	}

	if len(lint.problems) > 0 {
		sort.Strings(lint.problems)
		return 0, fmt.Errorf("public bytes encoding contract violated:\n  %s",
			strings.Join(lint.problems, "\n  "))
	}
	return len(lint.checked), nil
}

func (l *linter) reportf(format string, args ...any) {
	l.problems = append(l.problems, fmt.Sprintf(format, args...))
}

// checkOptionPlacement is rule 1: the option belongs on bytes and nowhere else.
func (l *linter) checkOptionPlacement(file, pkg string, message protoimage.Message) {
	for _, field := range message.Field {
		value, present := field.Encoding()
		if !present {
			continue
		}
		if field.Type != protoimage.TypeBytes {
			l.reportf("%s: %s.%s.%s has rest_bytes_encoding but is %s, not bytes",
				file, pkg, message.Name, field.Name, field.Type)
		}
		if !protoimage.KnownEncoding(value) {
			l.reportf("%s: %s.%s.%s declares unknown encoding %q",
				file, pkg, message.Name, field.Name, value)
		}
	}
	for _, nested := range message.NestedType {
		l.checkOptionPlacement(file, pkg, protoimage.Message{
			Name: message.Name + "." + nested.Name, Field: nested.Field, NestedType: nested.NestedType,
		})
	}
}

// checkClosure walks one request or response message and applies rules 2-4 to
// every message this repository owns. pathVariables is non-nil only for the
// request side, because a response never binds a path.
func (l *linter) checkClosure(origin, root string, pathVariables map[string]struct{}) {
	l.index.WalkBytes(root,
		func(leaf protoimage.Leaf) {
			l.checked[leaf.Owner+"."+leaf.Field.Name] = struct{}{}
			l.checkBytesLeaf(origin, leaf, pathVariables)
		},
		func(owner string, field protoimage.Field, entry protoimage.Message) {
			l.checkMap(origin, owner, field, entry)
		})
}

// checkMap is rule 3.
func (l *linter) checkMap(origin, owner string, field protoimage.Field, entry protoimage.Message) {
	for _, part := range entry.Field {
		if part.Type == protoimage.TypeBytes {
			l.reportf("%s (via %s): map field %s.%s has a bytes %s; V1 public services forbid it "+
				"because a map-value encoding is undefined",
				owner, origin, owner, field.Name, part.Name)
		}
	}
}

// checkBytesLeaf is rules 2 and 4.
func (l *linter) checkBytesLeaf(origin string, leaf protoimage.Leaf, pathVariables map[string]struct{}) {
	value, present := leaf.Field.Encoding()
	switch {
	case !present:
		l.reportf("%s.%s carries no rest_bytes_encoding but is reachable from %s",
			leaf.Owner, leaf.Field.Name, origin)
		return
	case value == protoimage.EncodingUnspecified:
		l.reportf("%s.%s declares REST_BYTES_ENCODING_UNSPECIFIED but is reachable from %s",
			leaf.Owner, leaf.Field.Name, origin)
		return
	}
	if _, bound := pathVariables[leaf.Path]; bound && value != protoimage.EncodingHash32 {
		l.reportf("%s.%s is bound to a URL path variable in %s but declares %s; "+
			"only HASH32_LOWER_HEX may enter a path", leaf.Owner, leaf.Field.Name, origin, value)
	}
}
