package dispatch

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type descriptorField struct {
	Name     string         `json:"name"`
	Number   uint32         `json:"number"`
	Type     string         `json:"type"`
	TypeName string         `json:"typeName"`
	Label    string         `json:"label"`
	Optional bool           `json:"proto3Optional"`
	Oneof    *int           `json:"oneofIndex"`
	Options  map[string]any `json:"options"`
}

// ValidateDescriptorImage compares the complete canonical field semantics with
// the built Buf image, including presence, integer sign/width and closed enums.
func ValidateDescriptorImage(data []byte) error {
	type enum struct {
		Name   string `json:"name"`
		Values []struct {
			Number uint64 `json:"number"`
		} `json:"value"`
	}
	var image struct {
		Files []struct {
			Package  string `json:"package"`
			Messages []struct {
				Name   string            `json:"name"`
				Fields []descriptorField `json:"field"`
			} `json:"messageType"`
			Enums []enum `json:"enumType"`
		} `json:"file"`
	}
	if err := json.Unmarshal(data, &image); err != nil {
		return err
	}
	enums := map[string]map[uint64]bool{}
	for _, file := range image.Files {
		for _, e := range file.Enums {
			values := map[uint64]bool{}
			for _, v := range e.Values {
				values[v.Number] = true
			}
			enums["."+file.Package+"."+e.Name] = values
		}
	}
	found := map[string]bool{}
	for _, file := range image.Files {
		for _, message := range file.Messages {
			name := file.Package + "." + message.Name
			spec, ok := protoTables[name]
			if !ok {
				continue
			}
			found[name] = true
			if len(spec) != len(message.Fields) {
				return fmt.Errorf("%s field count differs from pinned verifier", name)
			}
			for _, field := range message.Fields {
				actual := descriptorSpec(field, enums)
				if !reflect.DeepEqual(spec[field.Number], actual) {
					return fmt.Errorf("%s.%s differs from pinned canonical semantics", name, field.Name)
				}
			}
		}
	}
	for name := range protoTables {
		if !found[name] {
			return fmt.Errorf("missing pinned message %s", name)
		}
	}
	return nil
}

func descriptorSpec(field descriptorField, enums map[string]map[uint64]bool) fieldSpec {
	out := fieldSpec{name: field.Name, repeated: field.Label == "LABEL_REPEATED", optional: field.Optional}
	if field.Oneof != nil && !field.Optional {
		out.oneof = *field.Oneof + 1
	}
	switch field.Type {
	case "TYPE_MESSAGE":
		out.kind = kindMessage
		out.message = strings.TrimPrefix(field.TypeName, ".")
	case "TYPE_STRING":
		out.kind = kindString
	case "TYPE_BYTES":
		out.kind = kindBytes
	case "TYPE_UINT32":
		out.bits = 32
	case "TYPE_INT32":
		out.bits = 32
		out.signed = true
	case "TYPE_BOOL":
		out.boolean = true
	case "TYPE_ENUM":
		out.bits = 32
		out.enum = enums[field.TypeName]
	case "TYPE_UINT64":
	default:
		out.message = "unsupported canonical type: " + field.Type
	}
	out.address = field.Options["[cosmos_proto.scalar]"] == "cosmos.AddressString"
	out.hash = field.Options["[shared.v1.rest_bytes_encoding]"] == "REST_BYTES_ENCODING_HASH32_LOWER_HEX"
	return out
}
