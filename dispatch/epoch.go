package dispatch

import (
	"fmt"
	"math"
)

// EpochSeed is the verified epoch-start source for DispatchVrfInputV1.
type EpochSeed struct {
	Epoch           uint64
	ReferenceHeight uint64
	Randomness      [32]byte
}

// ResolveEpochSeed binds an order's height to the exact committed beacon the
// caller loaded from chain state. verified must come from that authority, never
// a ticket assertion. Epoch zero has no source; no substitute seed is allowed.
// This does not implement a second signing projection: pass its result through
// the existing DispatchVrfInputV1 SigningDigest.
func ResolveEpochSeed(orderHeight, epochLength, beaconHeight uint64, randomness []byte, verified bool) (EpochSeed, error) {
	var result EpochSeed
	if orderHeight == 0 || orderHeight > math.MaxInt64 || epochLength == 0 {
		return result, fmt.Errorf("invalid dispatch epoch height or length")
	}
	epoch := orderHeight / epochLength
	if epoch == 0 {
		return result, fmt.Errorf("epoch zero has no verified height-zero beacon")
	}
	// Multiplication cannot overflow: this product is <= orderHeight.
	reference := epoch * epochLength
	if beaconHeight != reference || !verified || len(randomness) != 32 {
		return result, fmt.Errorf("verified epoch-start beacon is unavailable")
	}
	result.Epoch, result.ReferenceHeight = epoch, reference
	copy(result.Randomness[:], randomness)
	return result, nil
}
