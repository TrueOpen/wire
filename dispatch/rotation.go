package dispatch

import (
	"fmt"
	"math"
)

// RotationWindowHardLimits are protocol clamps, never live governance values.
// Consumers bind these to their reviewed protocol version before enabling rotation.
type RotationWindowHardLimits struct {
	RecordDeadlineBlocks                  uint64 `json:"record_deadline_blocks"`
	DispatchCompensationClaimWindowBlocks uint64 `json:"dispatch_compensation_claim_window_blocks"`
	DispatchCompensationRebuttalBlocks    uint64 `json:"dispatch_compensation_rebuttal_blocks"`
	DispatchChallengeWindowBlocks         uint64 `json:"dispatch_challenge_window_blocks"`
	DispatchChallengeResponseBlocks       uint64 `json:"dispatch_challenge_response_blocks"`
}

// RotationSchedule freezes an inclusive old-dispatch cutoff and a safe epoch start.
// Old Task evidence can postpone activation further, by whole epochs only.
type RotationSchedule struct {
	OldMaterialCloseHeight uint64 `json:"old_material_close_height"`
	EffectiveHeight        uint64 `json:"effective_height"`
}

func rotationAdd(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, fmt.Errorf("service key rotation height overflow")
	}
	return a + b, nil
}

// ServiceKeyRotationSchedule uses the chain's current epoch start and length;
// it does not invent a second epoch origin. The first usable height is strictly
// after the inclusive cutoff, even when that cutoff is itself an epoch start.
func ServiceKeyRotationSchedule(registeredHeight, epochStartHeight, epochLength uint64, limits RotationWindowHardLimits) (RotationSchedule, error) {
	var empty RotationSchedule
	if registeredHeight == 0 || epochLength == 0 || epochStartHeight > registeredHeight || registeredHeight-epochStartHeight >= epochLength {
		return empty, fmt.Errorf("invalid service key rotation epoch scope")
	}
	for _, limit := range []uint64{limits.RecordDeadlineBlocks, limits.DispatchCompensationClaimWindowBlocks, limits.DispatchCompensationRebuttalBlocks, limits.DispatchChallengeWindowBlocks, limits.DispatchChallengeResponseBlocks} {
		if limit == 0 {
			return empty, fmt.Errorf("rotation window hard limits must be positive")
		}
	}
	claim, err := rotationAdd(limits.DispatchCompensationClaimWindowBlocks, limits.DispatchCompensationRebuttalBlocks)
	if err != nil {
		return empty, err
	}
	challenge, err := rotationAdd(limits.DispatchChallengeWindowBlocks, limits.DispatchChallengeResponseBlocks)
	if err != nil {
		return empty, err
	}
	closeHeight := registeredHeight
	for _, span := range []uint64{1, limits.RecordDeadlineBlocks, max(claim, challenge)} {
		closeHeight, err = rotationAdd(closeHeight, span)
		if err != nil {
			return empty, err
		}
	}
	first, err := rotationAdd(closeHeight, 1)
	if err != nil {
		return empty, err
	}
	effective := first
	if remainder := (first - epochStartHeight) % epochLength; remainder != 0 {
		effective, err = rotationAdd(first, epochLength-remainder)
		if err != nil {
			return empty, err
		}
	}
	return RotationSchedule{OldMaterialCloseHeight: closeHeight, EffectiveHeight: effective}, nil
}

// ServiceKeyRotationReady is the shared material/height gate. Call it with the
// next epoch's first height from the preceding EndBlock. The count includes only
// old-generation material dependencies, never future-generation operator duties.
// Node additionally enforces Cortex liability/stage guards and the global budget.
func ServiceKeyRotationReady(nextHeight uint64, schedule RotationSchedule, oldMaterialCount uint64) bool {
	return schedule.EffectiveHeight != 0 && nextHeight == schedule.EffectiveHeight && nextHeight > schedule.OldMaterialCloseHeight && oldMaterialCount == 0
}
