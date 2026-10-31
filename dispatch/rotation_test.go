package dispatch

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedServiceKeyRotationSchedules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "shared", "service_key_rotation_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Limits    RotationWindowHardLimits `json:"hard_limits"`
		Interval  uint64                   `json:"rotation_interval_blocks"`
		Schedules []struct {
			Name      string `json:"name"`
			Height    uint64 `json:"registered_height"`
			Start     uint64 `json:"epoch_start_height"`
			Length    uint64 `json:"epoch_length"`
			Effective uint64 `json:"effective_height"`
		} `json:"schedules"`
		Cases []struct {
			Name     string `json:"name"`
			Height   uint64 `json:"height"`
			Previous uint64 `json:"previous_retired_height"`
			Evidence uint64 `json:"previous_evidence_count"`
			Allowed  bool   `json:"allowed"`
		} `json:"registration_cases"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	interval, err := ServiceKeyRotationInterval(doc.Limits)
	if err != nil || interval != doc.Interval {
		t.Fatal(interval, err)
	}
	for _, row := range doc.Schedules {
		t.Run(row.Name, func(t *testing.T) {
			got, err := ServiceKeyRotationHeight(row.Height, row.Start, row.Length)
			if err != nil || got != row.Effective {
				t.Fatal(got, row.Effective, err)
			}
		})
	}
	for _, row := range doc.Cases {
		t.Run(row.Name, func(t *testing.T) {
			got, err := CanRegisterServiceKeyRotation(row.Height, row.Previous, row.Evidence, doc.Limits)
			if err != nil || got != row.Allowed {
				t.Fatal(got, row.Allowed, err)
			}
		})
	}
	if len(doc.Schedules) != 5 || len(doc.Cases) != 5 {
		t.Fatal("missing published boundaries")
	}
	for _, scope := range [][3]uint64{{0, 0, 10}, {100, 100, 0}, {100, 101, 10}, {105, 101, 10}, {111, 100, 10}, {math.MaxUint64, math.MaxUint64, 10}, {math.MaxUint64 - 1, math.MaxUint64 - 1, 1}} {
		if _, err := ServiceKeyRotationHeight(scope[0], scope[1], scope[2]); err == nil {
			t.Fatal("invalid or overflowing activation", scope)
		}
	}
	for _, limits := range []RotationWindowHardLimits{{}, {1, math.MaxUint64, 1, 1, 1}, {math.MaxUint64, 1, 1, 1, 1}, {1, 1, 1, math.MaxUint64, 1}} {
		if _, err := ServiceKeyRotationInterval(limits); err == nil {
			t.Fatal("invalid hard limits", limits)
		}
	}
	for _, scope := range [][3]uint64{{0, 0, 0}, {10, 11, 0}, {10, 0, 1}, {math.MaxUint64, math.MaxUint64 - 1, 0}} {
		if _, err := CanRegisterServiceKeyRotation(scope[0], scope[1], scope[2], doc.Limits); err == nil {
			t.Fatal("invalid previous scope", scope)
		}
	}
}
