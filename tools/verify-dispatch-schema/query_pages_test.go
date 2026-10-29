package main

import (
	"strings"
	"testing"
)

func TestQueryPageScopesTrackDescriptorAndBothDomains(t *testing.T) {
	image := []byte(`{"file":[{"package":"task.v1","messageType":[{"name":"EvidenceRequest","field":[{"name":"target","number":3},{"name":"page","number":5,"typeName":".shared.v1.QueryPageRequestV1"},{"name":"task_id","number":1}]}],"service":[{"name":"Query","method":[{"name":"Evidence","inputType":".task.v1.EvidenceRequest"}]}]}]}`)
	registry := `{"domains":[{"domain":"TRUEOPEN_QUERY_SELECTOR_V1","variants":[{"key":"/task.v1.Query/Evidence","fields":["task_id","target"]}]}]}`
	fixture := `{"vectors":[{"domain":"TRUEOPEN_QUERY_RPC_V1","rpc_method":"/task.v1.Query/Evidence","fields":[{"name":"rpc_method"}]},{"domain":"TRUEOPEN_QUERY_SELECTOR_V1","rpc_method":"/task.v1.Query/Evidence","variant":"/task.v1.Query/Evidence","fields":[{"name":"chain_id"},{"name":"rpc_method_digest"},{"name":"task_id"},{"name":"target"}]}]}`
	if err := validateQueryPageScopes(image, []byte(registry), []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, registry, fixture string }{
		{"missing registry", `{"domains":[]}`, fixture},
		{"reordered selector", strings.Replace(registry, `"task_id","target"`, `"target","task_id"`, 1), fixture},
		{"missing selector vector", registry, `{"vectors":[{"domain":"TRUEOPEN_QUERY_RPC_V1","rpc_method":"/task.v1.Query/Evidence","fields":[{"name":"rpc_method"}]}]}`},
		{"foreign RPC", registry, strings.ReplaceAll(fixture, "/task.v1.Query/Evidence", "/task.v1.Query/Foreign")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateQueryPageScopes(image, []byte(test.registry), []byte(test.fixture)); err == nil {
				t.Fatal("incomplete query scope accepted")
			}
		})
	}
}
