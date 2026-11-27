package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The two-step sampling vectors are recomputed here from their own inputs with
// an implementation written independently of the generator: the list hash, the
// aggregated position beacon and the position draw of
// docs/ANCHOR_TWO_STEP_SAMPLING_V1.md.
func TestAnchorTwoStepSamplingVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "v1", "task", "anchor_two_step_sampling_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name          string   `json:"name"`
			ChainID       string   `json:"chain_id"`
			TaskID        string   `json:"task_id_hex"`
			Rows          uint64   `json:"rows"`
			ListSize      uint64   `json:"list_size_bytes"`
			ListSHA256    string   `json:"list_sha256_hex"`
			ListHash      string   `json:"list_hash_hex"`
			SampleBeacon  string   `json:"sample_beacon_hex"`
			First         uint64   `json:"position_beacon_first_height"`
			Blocks        uint32   `json:"position_beacon_blocks"`
			Beacons       []string `json:"block_beacons_hex"`
			PositionBeacn string   `json:"position_beacon_hex"`
			Count         int      `json:"position_count"`
			Positions     []uint64 `json:"positions"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 5 {
		t.Fatalf("expected at least 5 vectors, found %d", len(doc.Vectors))
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	u64 := func(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
	u32 := func(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
	for _, v := range doc.Vectors {
		task := unhex(v.TaskID)
		if len(task) != 32 || v.Rows == 0 || v.ListSize != 32*v.Rows || int(v.Blocks) != len(v.Beacons) || v.Blocks < 2 {
			t.Fatalf("%s: malformed vector", v.Name)
		}
		// The list of a vector is defined by rule so the file stays small.
		list := sha256.New()
		tagged := sha256.New()
		tagged.Write([]byte("TRUEOPEN_ANCHOR_KV_LIST_V1"))
		tagged.Write([]byte(v.ChainID))
		tagged.Write(task)
		tagged.Write(u64(v.Rows))
		for i := uint64(0); i < v.Rows; i++ {
			entry := sha256.Sum256(append(append([]byte("vector-point"), task...), u32(uint32(i))...))
			list.Write(entry[:])
			tagged.Write(entry[:])
		}
		if got := hex.EncodeToString(list.Sum(nil)); got != v.ListSHA256 {
			t.Fatalf("%s: list bytes hash %s, vector says %s", v.Name, got, v.ListSHA256)
		}
		listHash := tagged.Sum(nil)
		if got := hex.EncodeToString(listHash); got != v.ListHash {
			t.Fatalf("%s: list_hash %s, vector says %s", v.Name, got, v.ListHash)
		}
		agg := sha256.New()
		agg.Write([]byte("TRUEOPEN_ANCHOR_POSITION_BEACON_V1"))
		agg.Write([]byte(v.ChainID))
		agg.Write(task)
		agg.Write(u64(v.First))
		agg.Write(u32(v.Blocks))
		for _, b := range v.Beacons {
			beacon := unhex(b)
			if len(beacon) != 32 {
				t.Fatalf("%s: a block beacon is not 32 bytes", v.Name)
			}
			agg.Write(beacon)
		}
		positionBeacon := agg.Sum(nil)
		if got := hex.EncodeToString(positionBeacon); got != v.PositionBeacn {
			t.Fatalf("%s: position_beacon %s, vector says %s", v.Name, got, v.PositionBeacn)
		}
		seen := map[uint64]bool{}
		var positions []uint64
		for i := uint32(0); len(positions) < v.Count && i < 64; i++ {
			h := sha256.New()
			h.Write([]byte("TRUEOPEN_ANCHOR_SAMPLE_V1"))
			h.Write([]byte(v.ChainID))
			h.Write(task)
			h.Write(unhex(v.SampleBeacon))
			h.Write(listHash)
			h.Write(positionBeacon)
			h.Write(u32(i))
			p := binary.BigEndian.Uint64(h.Sum(nil)[:8]) % v.Rows
			if !seen[p] {
				seen[p] = true
				positions = append(positions, p)
			}
		}
		sort.Slice(positions, func(a, b int) bool { return positions[a] < positions[b] })
		if len(positions) != len(v.Positions) {
			t.Fatalf("%s: %d positions, vector lists %d", v.Name, len(positions), len(v.Positions))
		}
		for i := range positions {
			if positions[i] != v.Positions[i] {
				t.Fatalf("%s: positions %v, vector says %v", v.Name, positions, v.Positions)
			}
		}
	}
}
