package dispatch

import "testing"

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
