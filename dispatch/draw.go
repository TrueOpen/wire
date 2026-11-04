package dispatch

import (
	"encoding/binary"
	"fmt"
	"math"
)

// WeightedMember is one member of the immutable, slot-ordered dispatch pool.
// Availability rosters filter the result; they never reseed or reorder it.
type WeightedMember struct {
	Slot   uint32
	Weight uint64
}

// DrawOrder computes the entire without-replacement order with unbiased
// rejection sampling. Randomness already binds the chain, epoch, session and
// order sequence. Task content and availability rosters never reseed the draw.
func DrawOrder(chainID string, randomness [32]byte, pool []WeightedMember, maxAttempts uint32) ([]uint32, error) {
	if maxAttempts == 0 || len(pool) == 0 || len(pool) > maxPoolMembers {
		return nil, fmt.Errorf("invalid draw limits")
	}
	remaining := append([]WeightedMember(nil), pool...)
	var total uint64
	for i, m := range remaining {
		if m.Weight == 0 || total > math.MaxUint64-m.Weight || i > 0 && remaining[i-1].Slot >= m.Slot {
			return nil, fmt.Errorf("invalid pool ordering or weight")
		}
		total += m.Weight
	}
	out := make([]uint32, 0, len(pool))
	var counter uint64
	for len(remaining) > 0 {
		var target uint64
		accepted := false
		for attempt := uint32(0); attempt < maxAttempts; attempt++ {
			digest := dispatchDrawDigest(chainID, randomness, counter)
			if counter == math.MaxUint64 {
				return nil, fmt.Errorf("draw counter overflow")
			}
			counter++
			x := binary.BigEndian.Uint64(digest[:8])
			threshold := -total % total
			if x < threshold {
				continue
			}
			target = x % total
			accepted = true
			break
		}
		if !accepted {
			return nil, fmt.Errorf("weighted draw attempts exhausted")
		}
		var cumulative uint64
		for i, m := range remaining {
			cumulative += m.Weight
			if cumulative > target {
				out = append(out, m.Slot)
				total -= m.Weight
				remaining = append(remaining[:i], remaining[i+1:]...)
				break
			}
		}
	}
	return out, nil
}

func dispatchDrawDigest(chainID string, randomness [32]byte, counter uint64) [32]byte {
	return HashFields("TRUEOPEN_WEIGHTED_DRAW_V1", []byte(chainID), []byte("WORKER_DISPATCH"), randomness[:], Uint64(counter))
}
