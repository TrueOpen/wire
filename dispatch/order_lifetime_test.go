package dispatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedOrderLifetimeBoundaries(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "order_lifetime_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Maximum uint64 `json:"maximum_protocol_blocks,string"`
		Cases   []struct {
			Name     string `json:"name"`
			Earliest uint64 `json:"earliest_submit_height,string"`
			Expiry   uint64 `json:"order_expire_height,string"`
			Maximum  uint64 `json:"max_order_lifetime_blocks,string"`
			Allowed  bool   `json:"allowed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Maximum != MaxOrderLifetimeBlocksV1 || len(document.Cases) < 10 {
		t.Fatal("missing lifetime boundaries")
	}
	for _, row := range document.Cases {
		t.Run(row.Name, func(t *testing.T) {
			if err := ValidateOrderLifetime(row.Earliest, row.Expiry, row.Maximum); (err == nil) != row.Allowed {
				t.Fatal(err, row.Allowed)
			}
		})
	}
}
