package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestQueryPageScopesTrackDescriptorAndBothDomains(t *testing.T) {
	image := []byte(`{"file":[{"package":"task.v1","messageType":[{"name":"EvidenceRequest","field":[{"name":"target","number":3},{"name":"page","number":5,"typeName":".shared.v1.QueryPageRequestV1"},{"name":"task_id","number":1}]}],"service":[{"name":"Query","method":[{"name":"Evidence","inputType":".task.v1.EvidenceRequest"}]}]}]}`)
	registry := `{"domains":[{"domain":"TRUEOPEN_QUERY_SELECTOR_V1","variants":[{"key":"/task.v1.Query/Evidence","fields":["task_id","target"]}]}]}`
	fixture := `{"vectors":[{"domain":"TRUEOPEN_QUERY_RPC_V1","rpc_method":"/task.v1.Query/Evidence","fields":[{"name":"rpc_method"}]},{"domain":"TRUEOPEN_QUERY_SELECTOR_V1","rpc_method":"/task.v1.Query/Evidence","variant":"/task.v1.Query/Evidence","replay":[{"name":"cross_chain","field":0,"value":"another-chain"}],"fields":[{"name":"chain_id"},{"name":"rpc_method_digest"},{"name":"task_id"},{"name":"target"}]}]}`
	if err := validateQueryPageScopes(image, []byte(registry), []byte(fixture)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, registry, fixture string }{
		{"missing registry", `{"domains":[]}`, fixture},
		{"reordered selector", strings.Replace(registry, `"task_id","target"`, `"target","task_id"`, 1), fixture},
		{"missing selector vector", registry, `{"vectors":[{"domain":"TRUEOPEN_QUERY_RPC_V1","rpc_method":"/task.v1.Query/Evidence","fields":[{"name":"rpc_method"}]}]}`},
		{"foreign RPC", registry, strings.ReplaceAll(fixture, "/task.v1.Query/Evidence", "/task.v1.Query/Foreign")},
		{"missing cross-chain replay", registry, strings.Replace(fixture, `,"replay":[{"name":"cross_chain","field":0,"value":"another-chain"}]`, "", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateQueryPageScopes(image, []byte(test.registry), []byte(test.fixture)); err == nil {
				t.Fatal("incomplete query scope accepted")
			}
		})
	}
	peerImage := strings.Replace(string(image), `"method":[`, `"method":[{"name":"Peer","inputType":".task.v1.EvidenceRequest"},`, 1)
	peerRegistry := strings.Replace(registry, `"variants":[`, `"variants":[{"key":"/task.v1.Query/Peer","fields":["task_id","target"]},`, 1)
	var peerFixture struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal([]byte(fixture), &peerFixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range append([]json.RawMessage(nil), peerFixture.Vectors...) {
		peerFixture.Vectors = append(peerFixture.Vectors, json.RawMessage(strings.ReplaceAll(string(row), "/task.v1.Query/Evidence", "/task.v1.Query/Peer")))
	}
	raw, err := json.Marshal(peerFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQueryPageScopes([]byte(peerImage), []byte(peerRegistry), raw); err == nil || !strings.Contains(err.Error(), "same-arity") {
		t.Fatalf("missing peer replay was not rejected: %v", err)
	}
}
