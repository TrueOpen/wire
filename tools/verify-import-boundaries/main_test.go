package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/tools/internal/protoimage"
)

// writeImage renders a descriptor image containing only what this check reads:
// file names and their dependency lists.
func writeImage(t *testing.T, deps map[string][]string) string {
	t.Helper()
	image := protoimage.Image{}
	for name, dependency := range deps {
		image.File = append(image.File, protoimage.File{Name: name, Dependency: dependency})
	}
	encoded, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// baseline is a descriptor tree that satisfies every rule: shared imports only
// shared, and task and bus reach shared but never hub.
func baseline() map[string][]string {
	return map[string][]string{
		"shared/v1/common.proto":   {"google/protobuf/descriptor.proto"},
		"shared/v1/evidence.proto": {"shared/v1/common.proto"},
		"hub/v1/common.proto":      {"shared/v1/common.proto"},
		"hub/v1/reward.proto":      {"hub/v1/common.proto"},
		"task/v1/task.proto":       {"shared/v1/evidence.proto"},
		"bus/v1/envelope.proto":    {"shared/v1/common.proto"},

		"google/protobuf/descriptor.proto": nil,
	}
}

func TestBaselineSatisfiesEveryRule(t *testing.T) {
	if err := run(writeImage(t, baseline())); err != nil {
		t.Fatalf("the compliant tree was rejected: %v", err)
	}
}

// TestTransitiveImportIsAViolation is the case that justifies walking the
// closure instead of reading import lines. No task file names a hub
// file, so a line-level check passes - but the generated Go package still
// depends on Hub, which is the thing the rule forbids.
func TestTransitiveImportIsAViolation(t *testing.T) {
	deps := baseline()
	deps["task/v1/settlement.proto"] = []string{"task/v1/indirect.proto"}
	deps["task/v1/indirect.proto"] = []string{"hub/v1/common.proto"}

	err := run(writeImage(t, deps))
	if err == nil {
		t.Fatal("a hub import two files deep was accepted")
	}
	for _, want := range []string{
		"task/v1/settlement.proto",
		"task/v1/indirect.proto",
		"hub/v1/common.proto",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the failure does not name %s, so it does not say which import to cut:\n%v", want, err)
		}
	}
}

func TestSharedIsNotAllowedToImportADomainPackage(t *testing.T) {
	for _, forbidden := range []string{
		"hub/v1/common.proto",
		"task/v1/task.proto",
		"bus/v1/envelope.proto",
	} {
		t.Run(forbidden, func(t *testing.T) {
			deps := baseline()
			deps["shared/v1/common.proto"] = []string{forbidden}
			if err := run(writeImage(t, deps)); err == nil {
				t.Fatalf("shared importing %s was accepted, so the leaf claim is not enforced", forbidden)
			}
		})
	}
}

func TestBusMayNotReachHub(t *testing.T) {
	deps := baseline()
	deps["bus/v1/envelope.proto"] = []string{"hub/v1/common.proto"}
	if err := run(writeImage(t, deps)); err == nil {
		t.Fatal("bus importing hub was accepted")
	}
}

// TestAnEmptySubjectFails covers the way a check like this usually stops
// working: not by being wrong, but by having nothing left to check. If every
// shared file were renamed away, the leaf rule would pass vacuously and the
// guarantee would disappear with no signal at all.
func TestAnEmptySubjectFails(t *testing.T) {
	deps := baseline()
	for name := range deps {
		if strings.HasPrefix(name, "shared/") {
			delete(deps, name)
		}
	}
	deps["hub/v1/common.proto"] = nil
	deps["task/v1/task.proto"] = nil
	deps["bus/v1/envelope.proto"] = nil

	err := run(writeImage(t, deps))
	if err == nil {
		t.Fatal("a rule with no subject passed vacuously")
	}
	if !strings.Contains(err.Error(), "checked nothing") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
}

// TestOneChainPerEndpointPerRoot keeps the failure readable. Every file that
// reaches a forbidden package is reported, because each one's own import list is
// what has to change - but a file reaching the same package by several routes is
// reported once, or the shortest chain would be buried among its own detours.
func TestOneChainPerEndpointPerRoot(t *testing.T) {
	deps := map[string][]string{
		"shared/v1/common.proto": nil,
		"hub/v1/common.proto":    nil,
		"bus/v1/envelope.proto":  {"shared/v1/common.proto"},
		"task/v1/task.proto": {
			"hub/v1/common.proto",
			"shared/v1/common.proto",
		},
	}
	// A second route from the same root to the same forbidden file, through a
	// package this repository does not own, so it adds no root of its own.
	deps["task/v1/task.proto"] = append(deps["task/v1/task.proto"], "google/protobuf/any.proto")
	deps["google/protobuf/any.proto"] = []string{"hub/v1/common.proto"}

	err := run(writeImage(t, deps))
	if err == nil {
		t.Fatal("accepted")
	}
	if got := strings.Count(err.Error(), "task.v1 does not reach hub.v1"); got != 1 {
		t.Fatalf("reported one root's single endpoint %d times:\n%v", got, err)
	}
}
