package dispatch

import (
	"encoding/json"
	"testing"
)

func TestDescriptorGuardRejectsSemanticDrift(t *testing.T) {
	// This independent descriptor fragment includes the complete stream binding,
	// including address options. A width/presence change cannot pass as wire type 0.
	const fragment = `{"file":[{"package":"nexus.v1","messageType":[{"name":"DispatchStreamBindingV1","field":[
	{"name":"schema_version","number":1,"type":"TYPE_UINT32"},
	{"name":"chain_id","number":2,"type":"TYPE_STRING"},
	{"name":"builder_operator","number":3,"type":"TYPE_STRING","options":{"[cosmos_proto.scalar]":"cosmos.AddressString"}},
	{"name":"cortex_operator","number":4,"type":"TYPE_STRING","options":{"[cosmos_proto.scalar]":"cosmos.AddressString"}},
	{"name":"service_authorization_nonce","number":5,"type":"TYPE_UINT64"},
	{"name":"stream_nonce","number":6,"type":"TYPE_BYTES"},
	{"name":"service_signature","number":7,"type":"TYPE_BYTES"}
	]}]}]}`
	previous := protoTables
	protoTables = map[string]messageSpec{"nexus.v1.DispatchStreamBindingV1": previous["nexus.v1.DispatchStreamBindingV1"]}
	t.Cleanup(func() { protoTables = previous })
	if err := ValidateDescriptorImage([]byte(fragment)); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		field int
		key   string
		value any
	}{
		{0, "type", "TYPE_UINT64"}, {0, "type", "TYPE_INT32"}, {0, "type", "TYPE_BOOL"},
		{0, "type", "TYPE_FIXED32"}, {0, "name", "other"}, {0, "number", 9},
		{1, "proto3Optional", true}, {1, "oneofIndex", 0}, {1, "label", "LABEL_REPEATED"},
		{2, "options", map[string]any{}}, {5, "options", map[string]any{"[shared.v1.rest_bytes_encoding]": "REST_BYTES_ENCODING_HASH32_LOWER_HEX"}},
	} {
		var image map[string]any
		if err := json.Unmarshal([]byte(fragment), &image); err != nil {
			t.Fatal(err)
		}
		fields := image["file"].([]any)[0].(map[string]any)["messageType"].([]any)[0].(map[string]any)["field"].([]any)
		fields[mutation.field].(map[string]any)[mutation.key] = mutation.value
		raw, err := json.Marshal(image)
		if err != nil {
			t.Fatal(err)
		}
		if ValidateDescriptorImage(raw) == nil {
			t.Fatalf("descriptor drift survived: %+v", mutation)
		}
	}
	if ValidateDescriptorImage([]byte(`{}`)) == nil || ValidateDescriptorImage([]byte(`bad json`)) == nil {
		t.Fatal("missing or malformed image accepted")
	}
}
