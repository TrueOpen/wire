package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The anchor commitment vector must frame exactly the fields its registry row
// lists, in order, and count the anchor_commit artifact size it commits to.
func TestWorkerAnchorCommitmentVectorFollowsTheRegistry(t *testing.T) {
	const domain = "TRUEOPEN_WORKER_ANCHOR_COMMITMENT_V1"
	raw, err := os.ReadFile(filepath.Join("..", "..", "registry", "v1", "domains.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Domains []struct {
			Domain string   `json:"domain"`
			Fields []string `json:"fields"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, row := range registry.Domains {
		if row.Domain == domain {
			want = row.Fields
		}
	}
	if want == nil {
		t.Fatalf("domain %s has no registry row", domain)
	}
	vector := integratedVector(t, loadIntegratedFixture(t, "task", "worker_anchor_commitment_v1.json"), domain)
	fields := vector["fields"].([]any)
	if len(fields) != len(want) {
		t.Fatalf("%d fields, the registry lists %d", len(fields), len(want))
	}
	for index, rawField := range fields {
		if name := rawField.(map[string]any)["name"]; name != want[index] {
			t.Fatalf("field %d is %v, the registry lists %q", index, name, want[index])
		}
	}
	if integratedField(t, vector, "schema_version")["value"].(json.Number).String() != "1" {
		t.Fatal("anchor commitment schema_version must be 1")
	}
	size := integratedField(t, vector, "anchor_commit_size_bytes")["value"]
	if fmt.Sprint(vector["expected_encoded_size_bytes"]) != fmt.Sprint(size) || fmt.Sprint(size) == "0" {
		t.Fatalf("encoded_size_bytes %v must be the positive anchor_commit size %v", vector["expected_encoded_size_bytes"], size)
	}
}

// The WORKER_ANCHOR_OPENING task-data vectors must all sign one Worker evidence
// reference with evidence kind 5: metadata, whole-object fetch and ranged fetch.
func TestTaskDataWorkerAnchorOpeningVectors(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "task_data_auth_v1.json")
	byName := map[string]map[string]any{}
	for _, raw := range doc["vectors"].([]any) {
		vector := raw.(map[string]any)
		byName[vector["name"].(string)] = vector
	}
	var first string
	for name, domain := range map[string]string{
		"task_data_metadata_body_v2_worker_anchor_opening":    "TRUEOPEN_TASK_DATA_METADATA_BODY_V2",
		"task_data_fetch_body_v2_worker_anchor_opening":       "TRUEOPEN_TASK_DATA_FETCH_BODY_V2",
		"task_data_fetch_body_v2_worker_anchor_opening_range": "TRUEOPEN_TASK_DATA_FETCH_BODY_V2",
	} {
		vector, ok := byName[name]
		if !ok {
			t.Fatalf("missing vector %s", name)
		}
		if vector["domain"] != domain {
			t.Fatalf("%s: domain %v, want %s", name, vector["domain"], domain)
		}
		ref := integratedField(t, vector, "object_ref")
		kinds := map[string]string{}
		for _, rawField := range ref["fields"].([]any) {
			field := rawField.(map[string]any)
			if value, ok := field["value"].(json.Number); ok {
				kinds[field["name"].(string)] = value.String()
			}
		}
		if kinds["evidence_kind"] != "5" || kinds["evidence_producer_kind"] != "1" {
			t.Fatalf("%s: evidence_kind %s from producer kind %s, want kind 5 from a Worker", name, kinds["evidence_kind"], kinds["evidence_producer_kind"])
		}
		encoded, err := json.Marshal(ref)
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = string(encoded)
		} else if string(encoded) != first {
			t.Fatalf("%s: object_ref differs from the other WORKER_ANCHOR_OPENING vectors", name)
		}
	}
}
