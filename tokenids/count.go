// Package tokenids defines display-only token statistics for the V1 token-ID
// artifacts. These statistics do not verify inference or authorize payment.
package tokenids

import "errors"

const (
	tokenWidthBytes        = 4
	tokenCountPrefixBytes  = 4
	artifactCountV1        = 2
	maxTokenIDFieldBytesV1 = 32 << 20

	// MaxTokenCountV1 follows the existing 32 MiB canonical field limit: one
	// uint32 count followed by that many uint32 token IDs.
	MaxTokenCountV1 = uint64((maxTokenIDFieldBytesV1 - tokenCountPrefixBytes) / tokenWidthBytes)
)

// ErrInputTokenCountUnavailable means the supplied metadata cannot yield a
// valid display count. Callers must not treat the returned zero as a statistic.
var ErrInputTokenCountUnavailable = errors.New("tokenids: input token count unavailable")

// InputTokenCountV1 derives a positive input count from the WORKER_TOKEN_OPENING
// encoded size and generated_token_count of the same accepted receipt.
// The size includes only the input and generated token-ID artifacts, each with
// its own count prefix. It excludes manifests, parameters and hash framing.
// The caller must establish receipt acceptance, retained commitments and the
// V1 token encoding; this function neither reads chain state nor proves that
// the Worker reported the real token counts. Never use its result for billing,
// settlement, weights, budgets or signing/business digests.
func InputTokenCountV1(encodedSizeBytes, generatedTokenCount uint64) (uint64, error) {
	const prefixes = artifactCountV1 * tokenCountPrefixBytes
	if encodedSizeBytes < prefixes || (encodedSizeBytes-prefixes)%tokenWidthBytes != 0 {
		return 0, ErrInputTokenCountUnavailable
	}
	totalTokenCount := (encodedSizeBytes - prefixes) / tokenWidthBytes
	if generatedTokenCount >= totalTokenCount {
		return 0, ErrInputTokenCountUnavailable
	}
	inputTokenCount := totalTokenCount - generatedTokenCount
	if inputTokenCount > MaxTokenCountV1 || generatedTokenCount > MaxTokenCountV1 {
		return 0, ErrInputTokenCountUnavailable
	}
	return inputTokenCount, nil
}
