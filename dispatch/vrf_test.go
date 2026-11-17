package dispatch

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedDispatchVRFUsesIndependentReduction(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		VRF map[string]string `json:"vrf"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	v := doc.VRF
	key := ed25519.NewKeyFromSeed(hexBytes(t, v["private_seed_hex"]))
	alpha := hexBytes(t, v["alpha_hex"])
	proof, randomness, err := ProveDispatchVRF(key, alpha)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(proof) != v["proof_hex"] || hex.EncodeToString(randomness[:]) != v["randomness_hex"] {
		t.Fatal("published ELL2 proof or reduction changed")
	}
	if err = VerifyDispatchVRF(hexBytes(t, v["public_key_hex"]), alpha, proof, randomness[:]); err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), alpha...)
	wrong[0] ^= 1
	if VerifyDispatchVRF(key.Public().(ed25519.PublicKey), wrong, proof, randomness[:]) == nil {
		t.Fatal("wrong VRF input accepted")
	}
	bad := append([]byte(nil), proof...)
	bad[20] ^= 1
	if VerifyDispatchVRF(key.Public().(ed25519.PublicKey), alpha, bad, randomness[:]) == nil {
		t.Fatal("tampered VRF proof accepted")
	}
	if VerifyDispatchVRF(key.Public().(ed25519.PublicKey), alpha, proof, bytes.Repeat([]byte{0}, 32)) == nil {
		t.Fatal("unrelated randomness accepted")
	}
	if _, err = ReduceDispatchRandomness(make([]byte, 32)); err == nil {
		t.Fatal("short beta accepted")
	}
}
