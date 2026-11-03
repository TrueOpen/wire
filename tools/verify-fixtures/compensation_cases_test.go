package main

import (
	"maps"
	"testing"
)

// These are consumer preconditions, not a second claim-admission implementation.
// In particular, merging an override must not erase the row whose status or
// replay receipt is the subject of the case.
func TestCompensationClaimFixtureRowsAreConsistent(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "dispatch_compensation_v1.json")
	defaults := doc["claim_defaults"].(map[string]any)
	cases := doc["claim_cases"].([]any)
	if len(cases) == 0 {
		t.Fatal("missing compensation claim cases")
	}
	for _, value := range cases {
		row := maps.Clone(defaults)
		maps.Copy(row, value.(map[string]any))
		t.Run(row["name"].(string), func(t *testing.T) {
			exists, ok := row["claim_exists"].(bool)
			if !ok {
				t.Fatal("claim existence must be explicit after applying defaults")
			}
			status, _ := row["existing_claim_status"].(string)
			replay, _ := row["exact_ticket_replay"].(bool)
			if exists != (status != "") || replay && !exists {
				t.Fatalf("contradictory claim preconditions: exists=%t status=%q replay=%t", exists, status, replay)
			}
		})
	}
}
