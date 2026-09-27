// Command verify-params-fixture checks that the published parameter
// commitment vectors encode every field of the parameter messages they claim
// to encode. A field added to a params message without a fixture entry would
// otherwise leave the published digest computed over a message that no longer
// exists, and every implementation that encodes the real message would
// disagree with it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

type fixtureField struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Fields []fixtureField `json:"fields"`
}

type fixtureVector struct {
	Name         string         `json:"name"`
	ProtoMessage string         `json:"proto_message"`
	Fields       []fixtureField `json:"fields"`
}

func main() {
	imagePath := flag.String("image", "../build/image.json", "buf JSON descriptor image")
	fixturePath := flag.String("fixture", "../testdata/v1/shared/params_v1.json", "parameter commitment fixture")
	flag.Parse()

	count, err := verify(*imagePath, *fixturePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("verified %d parameter field(s) against the descriptor\n", count)
}

func verify(imagePath, fixturePath string) (int, error) {
	image, err := protoimage.Load(imagePath)
	if err != nil {
		return 0, err
	}
	index := protoimage.NewIndex(image)
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		return 0, err
	}
	var doc struct {
		Vectors []fixtureVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("decode %s: %w", fixturePath, err)
	}
	if len(doc.Vectors) == 0 {
		return 0, fmt.Errorf("%s publishes no vectors", fixturePath)
	}
	var problems []string
	count := 0
	for _, vector := range doc.Vectors {
		if vector.ProtoMessage == "" {
			problems = append(problems, fmt.Sprintf("%s: no proto_message", vector.Name))
			continue
		}
		var params *fixtureField
		for i := range vector.Fields {
			if vector.Fields[i].Name == "params" {
				params = &vector.Fields[i]
			}
		}
		if params == nil {
			problems = append(problems, fmt.Sprintf("%s: no params frame", vector.Name))
			continue
		}
		count += compare(index, "."+vector.ProtoMessage, params.Fields, vector.Name+".params", &problems)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return 0, fmt.Errorf("parameter fixture does not cover its messages:\n  %s", strings.Join(problems, "\n  "))
	}
	return count, nil
}

// compare requires the fixture frame to list exactly the message's fields, by
// name, in ascending field-number order, and recurses into singular message
// fields. A repeated field is a frame that starts with element_count.
func compare(index *protoimage.Index, typeName string, got []fixtureField, where string, problems *[]string) int {
	message, ok := index.Message(typeName)
	if !ok {
		*problems = append(*problems, fmt.Sprintf("%s: %s is missing from the descriptor", where, typeName))
		return 0
	}
	fields := append([]protoimage.Field(nil), message.Field...)
	sort.Slice(fields, func(i, j int) bool { return fields[i].Number < fields[j].Number })
	want := make([]string, len(fields))
	for i, field := range fields {
		want[i] = field.Name
	}
	have := make([]string, len(got))
	for i, field := range got {
		have[i] = field.Name
	}
	if strings.Join(want, ",") != strings.Join(have, ",") {
		*problems = append(*problems, fmt.Sprintf("%s (%s): fixture fields [%s], descriptor fields [%s]",
			where, strings.TrimPrefix(typeName, "."), strings.Join(have, ","), strings.Join(want, ",")))
		return 0
	}
	count := 0
	for i, field := range fields {
		path := where + "." + field.Name
		switch {
		case field.Repeated():
			if got[i].Type != "frame" || len(got[i].Fields) == 0 || got[i].Fields[0].Name != "element_count" {
				*problems = append(*problems, fmt.Sprintf("%s: repeated field is not a frame led by element_count", path))
			}
			count++
		case field.Type == protoimage.TypeMessage:
			if got[i].Type != "frame" {
				*problems = append(*problems, fmt.Sprintf("%s: message field is not a frame", path))
				continue
			}
			count += compare(index, field.TypeName, got[i].Fields, path, problems)
		default:
			count++
		}
	}
	return count
}
