package dispatch

import (
	"fmt"
	"math"
)

// RotationWindowHardLimits are protocol clamps, never live governance values.
// They protect the previous proof generation before another registration.
type RotationWindowHardLimits struct {
	RecordDeadlineBlocks                  uint64 `json:"record_deadline_blocks"`
	DispatchCompensationClaimWindowBlocks uint64 `json:"dispatch_compensation_claim_window_blocks"`
	DispatchCompensationRebuttalBlocks    uint64 `json:"dispatch_compensation_rebuttal_blocks"`
	DispatchChallengeWindowBlocks         uint64 `json:"dispatch_challenge_window_blocks"`
	DispatchChallengeResponseBlocks       uint64 `json:"dispatch_challenge_response_blocks"`
}

func rotationAdd(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, fmt.Errorf("service key rotation height overflow")
	}
	return a + b, nil
}

// ServiceKeyRotationHeight returns the fixed E+2 start using the chain's
// zero-based epoch. Old-material counts and windows do not change this height.
func ServiceKeyRotationHeight(registeredHeight, epochStartHeight, epochLength uint64) (uint64, error) {
	if registeredHeight == 0 || epochLength == 0 || epochStartHeight%epochLength != 0 || epochStartHeight > registeredHeight || registeredHeight-epochStartHeight >= epochLength {
		return 0, fmt.Errorf("invalid service key rotation epoch scope")
	}
	next, err := rotationAdd(epochStartHeight, epochLength)
	if err != nil {
		return 0, err
	}
	return rotationAdd(next, epochLength)
}

// ServiceKeyRotationInterval protects the previous key before another rotation
// can be registered. It does not schedule the pending key's activation.
func ServiceKeyRotationInterval(limits RotationWindowHardLimits) (uint64, error) {
	for _, limit := range []uint64{limits.RecordDeadlineBlocks, limits.DispatchCompensationClaimWindowBlocks, limits.DispatchCompensationRebuttalBlocks, limits.DispatchChallengeWindowBlocks, limits.DispatchChallengeResponseBlocks} {
		if limit == 0 {
			return 0, fmt.Errorf("rotation window hard limits must be positive")
		}
	}
	claim, err := rotationAdd(limits.DispatchCompensationClaimWindowBlocks, limits.DispatchCompensationRebuttalBlocks)
	if err != nil {
		return 0, err
	}
	challenge, err := rotationAdd(limits.DispatchChallengeWindowBlocks, limits.DispatchChallengeResponseBlocks)
	if err != nil {
		return 0, err
	}
	interval, err := rotationAdd(1, limits.RecordDeadlineBlocks)
	if err != nil {
		return 0, err
	}
	return rotationAdd(interval, max(claim, challenge))
}

// CanRegisterServiceKeyRotation checks the previous generation's protection.
// A zero previousRetiredHeight means no previous key. Current group duties and
// liability are deliberately absent from this gate.
func CanRegisterServiceKeyRotation(height, previousRetiredHeight, previousEvidenceCount uint64, limits RotationWindowHardLimits) (bool, error) {
	interval, err := ServiceKeyRotationInterval(limits)
	if err != nil {
		return false, err
	}
	if height == 0 || previousRetiredHeight > height || previousRetiredHeight == 0 && previousEvidenceCount != 0 {
		return false, fmt.Errorf("invalid previous service key protection scope")
	}
	if previousRetiredHeight == 0 {
		return true, nil
	}
	eligible, err := rotationAdd(previousRetiredHeight, interval)
	if err != nil {
		return false, err
	}
	return height >= eligible && previousEvidenceCount == 0, nil
}
