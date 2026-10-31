package dispatch

import "fmt"

// OutputChunkDigest binds a cumulative output prefix to exactly one dispatch.
// For objective evidence, ticketHash must come from the accepted InferReceipt.
func OutputChunkDigest(chainID string, taskHash, ticketHash [32]byte, seq uint64, root [32]byte) [32]byte {
	return HashFields("TRUEOPEN_OUTPUT_CHUNK_V1", []byte(chainID), taskHash[:], ticketHash[:], Uint64(seq), root[:])
}

// OutputFinDigest binds the final declaration to that same dispatch attempt.
// FinishReasonV1 values 1..6 are the complete successful termination set.
func OutputFinDigest(chainID string, taskHash, ticketHash [32]byte, seq uint64, root [32]byte, finishReason uint32) ([32]byte, error) {
	if finishReason < 1 || finishReason > 6 {
		return [32]byte{}, fmt.Errorf("invalid finish reason")
	}
	return HashFields("TRUEOPEN_OUTPUT_FIN_V1", []byte(chainID), taskHash[:], ticketHash[:], Uint64(seq), root[:], Uint32(finishReason)), nil
}
