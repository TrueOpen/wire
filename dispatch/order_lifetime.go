package dispatch

import (
	"fmt"
	"math"
)

// MaxOrderLifetimeBlocksV1 keeps admitted orders inside unreferenced epoch-body
// retention. A Session's positive governed value may be lower than this clamp.
const MaxOrderLifetimeBlocksV1 = uint64(240)

// PoolBodyRetentionBlocks preserves an unreferenced epoch body for both the
// hard order lifetime and the chain's immutable old-material proof windows.
func PoolBodyRetentionBlocks(limits RotationWindowHardLimits) (uint64, error) {
	interval, err := ServiceKeyRotationInterval(limits)
	if err != nil {
		return 0, err
	}
	return max(interval, MaxOrderLifetimeBlocksV1+1), nil
}

// ValidateOrderLifetime checks the signed expiry without adding to a near-limit
// height. Same-block expiry remains valid; the earliest height is not a timestamp.
func ValidateOrderLifetime(earliest, expiry, maximum uint64) error {
	if maximum == 0 || maximum > MaxOrderLifetimeBlocksV1 {
		return fmt.Errorf("max_order_lifetime_blocks must be in 1..%d", MaxOrderLifetimeBlocksV1)
	}
	if earliest == 0 || earliest > math.MaxInt64 || expiry > math.MaxInt64 || expiry < earliest || expiry-earliest > maximum {
		return fmt.Errorf("order expiry is outside its frozen lifetime")
	}
	return nil
}
