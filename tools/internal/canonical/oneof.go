// Package canonical shares fixture framing between the release verifiers.
package canonical

import (
	"encoding/binary"
	"fmt"
)

// Oneof encodes a proto field number followed by the selected payload frame.
func Oneof(fieldNumber uint64, payloadFields ...[]byte) ([]byte, error) {
	if fieldNumber == 0 || fieldNumber >= 1<<29 || len(payloadFields) == 0 {
		return nil, fmt.Errorf("oneof requires a proto field number and selected payload fields")
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(fieldNumber))
	for _, field := range payloadFields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return out, nil
}
