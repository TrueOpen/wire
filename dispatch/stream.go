package dispatch

import (
	"bytes"
	"fmt"
)

// StreamNonceSize is the authenticated per-connection nonce width.
const StreamNonceSize = 32

// StreamSchemaVersion is the only DispatchStreamBindingV1 version.
const StreamSchemaVersion = 1

func validateStreamShape(name string, fields decoded) error {
	switch name {
	case "nexus.v1.DispatchInputResponseV1":
		index, count, total := scalarAt(fields, 6), scalarAt(fields, 7), scalarAt(fields, 4)
		chunk := uint64(len(bytesAt(fields, 5)))
		if count == 0 || index >= count || chunk > total || count == 1 && chunk != total || count > 1 && (chunk == 0 || count > total) {
			return fmt.Errorf("%w: input chunk index/count or whole-input size", ErrDecode)
		}
	case "nexus.v1.DispatchStreamBindingV1":
		if len(fields[1]) != 1 || fields[1][0].varint != StreamSchemaVersion || len(fields[6]) != 1 || len(fields[6][0].bytes) != StreamNonceSize {
			return fmt.Errorf("%w: stream binding requires schema 1 and a raw32 nonce", ErrDecode)
		}
	case "nexus.v1.DispatchStreamFrameV1":
		if len(fields[1]) != 1 || len(fields[1][0].bytes) != StreamNonceSize {
			return fmt.Errorf("%w: stream frame nonce must be raw32", ErrDecode)
		}
		cursor := uint64(0)
		if len(fields[2]) != 0 {
			cursor = fields[2][0].varint
		}
		var message uint32
		for number := range fields {
			if number >= 3 {
				message = number
			}
		}
		if message == 0 {
			return fmt.Errorf("%w: stream frame requires one message", ErrDecode)
		}
		control := message == 3 || message == 17 || message == 18
		if control && cursor != 0 || !control && cursor == 0 {
			return fmt.Errorf("%w: cursor zero is reserved for transport frames", ErrDecode)
		}
		if message == 3 {
			binding, err := decode("nexus.v1.DispatchStreamBindingV1", fields[3][0].bytes, 1)
			if err != nil {
				return err
			}
			if !bytes.Equal(fields[1][0].bytes, binding[6][0].bytes) {
				return fmt.Errorf("%w: frame and binding nonce differ", ErrDecode)
			}
		}
	}
	return nil
}
