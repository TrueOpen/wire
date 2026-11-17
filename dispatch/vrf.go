package dispatch

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	voied25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519/extra/ecvrf"
)

// DispatchRandomnessReductionDomain is a suite-specific raw-beta reduction
// context, independent from the beacon's reduction. It is not a new framing.
const DispatchRandomnessReductionDomain = "TRUEOPEN_DISPATCH_RANDOMNESS_V1"

// ReduceDispatchRandomness reduces the RFC 9381 64-byte beta to raw32.
func ReduceDispatchRandomness(beta []byte) ([32]byte, error) {
	if len(beta) != 64 {
		return [32]byte{}, fmt.Errorf("ECVRF beta must be 64 bytes")
	}
	prefix := append([]byte(DispatchRandomnessReductionDomain), 0)
	return sha256.Sum256(append(prefix, beta...)), nil
}

// ProveDispatchVRF reuses the established ELL2 suite implementation; it adds
// only the dispatch input shape and the independent randomness reduction.
func ProveDispatchVRF(key ed25519.PrivateKey, alpha []byte) ([]byte, [32]byte, error) {
	if len(key) != ed25519.PrivateKeySize || len(alpha) != 32 {
		return nil, [32]byte{}, fmt.Errorf("invalid dispatch VRF input")
	}
	proof := ecvrf.Prove(voied25519.PrivateKey(key), alpha)
	beta, err := ecvrf.ProofToHash(proof)
	if err != nil {
		return nil, [32]byte{}, err
	}
	randomness, err := ReduceDispatchRandomness(beta)
	return proof, randomness, err
}

// VerifyDispatchVRF binds an exact raw32 alpha, raw80 proof and raw32 result.
func VerifyDispatchVRF(publicKey, alpha, proof, randomness []byte) error {
	if len(publicKey) != 32 || len(alpha) != 32 || len(proof) != 80 || len(randomness) != 32 {
		return fmt.Errorf("invalid dispatch VRF shape")
	}
	valid, beta := ecvrf.Verify(voied25519.PublicKey(publicKey), proof, alpha)
	if !valid {
		return fmt.Errorf("dispatch VRF proof rejected")
	}
	want, err := ReduceDispatchRandomness(beta)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(want[:], randomness) != 1 {
		return fmt.Errorf("dispatch VRF randomness mismatch")
	}
	return nil
}
