package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestInputTokenCountCasesRejectDrift(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/v1/task/token_ids_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInputTokenCountCases(raw); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(*inputTokenCountFixture)
	}{
		{"missing cases", func(f *inputTokenCountFixture) { f.Derivation.Cases = nil }},
		{"missing source", func(f *inputTokenCountFixture) { f.Derivation.SourceCase = "missing" }},
		{"duplicate case", func(f *inputTokenCountFixture) {
			f.Derivation.Cases = append(f.Derivation.Cases, f.Derivation.Cases[0])
		}},
		{"changed raw input count", func(f *inputTokenCountFixture) { f.Vectors[0].Count++ }},
		{"fabricated expected count", func(f *inputTokenCountFixture) { value := "9"; f.Derivation.Cases[0].Input = &value }},
		{"valid but unrelated source", func(f *inputTokenCountFixture) {
			f.Derivation.Cases[0].Size = "32"
			value := "3"
			f.Derivation.Cases[0].Input = &value
		}},
		{"overflow size", func(f *inputTokenCountFixture) { f.Derivation.Cases[0].Size = "18446744073709551616" }},
		{"missing generated count", func(f *inputTokenCountFixture) { f.Derivation.Cases[0].Generated = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var fixture inputTokenCountFixture
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			test.edit(&fixture)
			changed, err := json.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateInputTokenCountCases(changed); err == nil {
				t.Fatal("invalid derivation fixture was accepted")
			}
		})
	}
	// The public fixture walker must execute the new cases as part of its
	// normal path; a verifier existing only in a unit test would leave CI blind.
	bad := bytes.Replace(raw, []byte(`"input_token_count": "2"`), []byte(`"input_token_count": "9"`), 1)
	path := t.TempDir() + "/token_ids_v1.json"
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedVectors(path, "task/token_ids_v1.json"); err == nil {
		t.Fatal("the manifest vector gate did not execute input-count validation")
	}
}
