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
		Schedules []struct {
			Name             string `json:"name"`
			RegisteredHeight uint64 `json:"registered_height"`
			EpochStart       uint64 `json:"epoch_start_height"`
			EpochLength      uint64 `json:"epoch_length"`
			RotationSchedule
		} `json:"schedules"`
		Cases []struct {
			Name       string `json:"name"`
			NextHeight uint64 `json:"next_height"`
			OldCount   uint64 `json:"old_material_count"`
			Ready      bool   `json:"ready"`
		} `json:"activation_cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, row := range doc.Schedules {
		t.Run(row.Name, func(t *testing.T) {
			got, err := ServiceKeyRotationSchedule(row.RegisteredHeight, row.EpochStart, row.EpochLength, doc.Limits)
			if err != nil || got != row.RotationSchedule {
				t.Fatal("rotation differs from independent schedule", got, row.RotationSchedule, err)
			}
		})
	}
	if len(doc.Schedules) != 4 || len(doc.Cases) != 4 {
		t.Fatal("missing schedule or activation boundary")
	}
	for _, row := range doc.Cases {
		if got := ServiceKeyRotationReady(row.NextHeight, doc.Schedules[0].RotationSchedule, row.OldCount); got != row.Ready {
			t.Fatal(row.Name, got)
		}
	}
	if ServiceKeyRotationReady(180, RotationSchedule{180, 180}, 0) || ServiceKeyRotationReady(0, RotationSchedule{}, 0) {
		t.Fatal("inclusive cutoff or unspecified activation ignored")
	}
	for _, scope := range [][3]uint64{{0, 0, 10}, {100, 100, 0}, {100, 101, 10}, {111, 100, 10}, {math.MaxUint64, math.MaxUint64, 10}} {
		if _, err := ServiceKeyRotationSchedule(scope[0], scope[1], scope[2], doc.Limits); err == nil {
			t.Fatal("invalid or overflowing schedule admitted", scope)
		}
	}
	bad := doc.Limits
	bad.DispatchCompensationClaimWindowBlocks = math.MaxUint64
	if _, err := ServiceKeyRotationSchedule(100, 100, 10, bad); err == nil {
		t.Fatal("window-sum overflow admitted")
	}
	if _, err := ServiceKeyRotationSchedule(100, 100, 10, RotationWindowHardLimits{}); err == nil {
		t.Fatal("unspecified protocol clamps admitted")
	}
}
