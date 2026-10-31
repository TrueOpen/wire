package dispatch

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedHandraiseTreesAndInclusionProofs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tree struct {
			SignedRoot string `json:"signed_root_vector"`
			Cases      []struct {
				Name     string   `json:"name"`
				Standing []string `json:"standing_digests_hex"`
				Leaves   []string `json:"leaf_digests_hex"`
				Root     string   `json:"root_hex"`
				Proofs   []struct {
					Index    uint32   `json:"leaf_index"`
					Siblings []string `json:"siblings_hex"`
				} `json:"proofs"`
			} `json:"cases"`
		} `json:"handraise_merkle"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Tree.Cases) != 3 {
		t.Fatal("missing empty/single/odd tree vectors")
	}
	for _, row := range doc.Tree.Cases {
		t.Run(row.Name, func(t *testing.T) {
			if len(row.Standing) != len(row.Leaves) || len(row.Proofs) != len(row.Leaves) {
				t.Fatal("tree inputs or proof coverage are incomplete")
			}
			leaves := make([][32]byte, len(row.Leaves))
			for i, text := range row.Leaves {
				standing := array32(t, row.Standing[i])
				if i > 0 && bytes.Compare(hexBytes(t, row.Standing[i-1]), standing[:]) >= 0 {
					t.Fatal("standing digests are not strictly ordered")
				}
				leaves[i] = array32(t, text)
				got, err := HandraiseLeafDigest(standing, true, 1, 0)
				if err != nil || got != leaves[i] {
					t.Fatal("admission leaf differs from independent vector", err)
				}
			}
			root := array32(t, row.Root)
			if got := HandraiseRoot(leaves); got != root {
				t.Fatal("tree root differs from independent vector")
			}
			for _, p := range row.Proofs {
				if int(p.Index) >= len(leaves) {
					t.Fatal("proof index out of bounds")
				}
				siblings := make([][32]byte, len(p.Siblings))
				for i, text := range p.Siblings {
					siblings[i] = array32(t, text)
				}
				if !VerifyHandraiseProof(root, leaves[p.Index], p.Index, uint32(len(leaves)), siblings) {
					t.Fatal("independent inclusion proof rejected")
				}
				generated, err := HandraiseProof(leaves, p.Index)
				if err != nil || len(generated) != len(siblings) {
					t.Fatal("proof generator differs from published path", err)
				}
				for i := range siblings {
					if generated[i] != siblings[i] {
						t.Fatal("proof sibling mismatch")
					}
				}
				if VerifyHandraiseProof(root, leaves[p.Index], p.Index, uint32(len(leaves)), append(siblings, [32]byte{})) {
					t.Fatal("extra sibling accepted")
				}
			}
			if row.Name == "single" {
				found := false
				for _, signed := range published(t) {
					if signed.Name != doc.Tree.SignedRoot {
						continue
					}
					d, err := decode(signed.MessageName, hexBytes(t, signed.Protobuf), 0)
					if err != nil || !bytes.Equal(bytesAt(d, 6), root[:]) || scalarAt(d, 5) != 1 {
						t.Fatal("signed root is not the published leaf's root", err)
					}
					found = true
				}
				if !found {
					t.Fatal("missing linked signed root")
				}
			}
		})
	}
}

func TestHandraiseProofIncludesOddNodePromotion(t *testing.T) {
	leaves := make([][32]byte, 3)
	for i := range leaves {
		var standing [32]byte
		standing[0] = byte(i + 1)
		leaf, err := HandraiseLeafDigest(standing, true, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = leaf
	}
	root := HandraiseRoot(leaves)
	for i := range leaves {
		proof, err := HandraiseProof(leaves, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyHandraiseProof(root, leaves[i], uint32(i), 3, proof) {
			t.Fatal("valid proof rejected")
		}
		wrong := leaves[i]
		wrong[0] ^= 1
		if VerifyHandraiseProof(root, wrong, uint32(i), 3, proof) {
			t.Fatal("tampered leaf accepted")
		}
		if VerifyHandraiseProof(root, leaves[i], uint32(i), 3, append(proof, [32]byte{})) {
			t.Fatal("extra sibling accepted")
		}
	}
	if _, err := HandraiseLeafDigest(leaves[0], true, 2, 10); err == nil {
		t.Fatal("admitted leaf carries a rejection")
	}
	if _, err := HandraiseLeafDigest(leaves[0], false, 2, 0); err == nil {
		t.Fatal("RTT rejection omits measurement")
	}
}
