package dispatch

import (
	"bytes"
	"fmt"
	"math"
)

// MaxBuilderSyncEntries bounds items and output chunks in one 1 MiB request.
const MaxBuilderSyncEntries = 128

func validateBuilderSyncShape(name string, fields decoded) error {
	switch name {
	case "nexus.v1.SyncRequest":
		if len(fields[1]) != 1 {
			return fmt.Errorf("%w: sync batch is required", ErrDecode)
		}
		if len(fields[2]) != 0 && len(bytesAt(fields, 2)) != SignatureSize {
			return fmt.Errorf("%w: sync signature must be raw64", ErrDecode)
		}
	case "nexus.v1.BuilderSyncBatchV1":
		if scalarAt(fields, 1) != 1 || len(bytesAt(fields, 2)) == 0 || len(bytesAt(fields, 7)) == 0 || bytes.Equal(bytesAt(fields, 3), bytesAt(fields, 4)) || len(fields[9]) == 0 && len(fields[10]) == 0 || len(fields[9]) > MaxBuilderSyncEntries {
			return fmt.Errorf("%w: sync batch scope, version or size", ErrDecode)
		}
		var previous uint64
		for i, raw := range fields[9] {
			item, err := decode("nexus.v1.BuilderSyncItemV1", raw.bytes, 1)
			if err != nil {
				return err
			}
			sequence := scalarAt(item, 1)
			if sequence == 0 || i > 0 && (previous == math.MaxUint64 || sequence != previous+1) {
				return fmt.Errorf("%w: sync item sequences must be consecutive", ErrDecode)
			}
			previous = sequence
		}
		return validateBuilderSyncScopes(fields)
	case "nexus.v1.BuilderSyncItemV1":
		selected := false
		for number := uint32(2); number <= 6; number++ {
			selected = selected || len(fields[number]) != 0
		}
		if scalarAt(fields, 1) == 0 || !selected {
			return fmt.Errorf("%w: sync item requires a positive sequence and one payload", ErrDecode)
		}
	case "nexus.v1.BuilderSyncInputChunkV1":
		offset, size, data := scalarAt(fields, 5), scalarAt(fields, 3), uint64(len(bytesAt(fields, 6)))
		if offset > size || data > size-offset {
			return fmt.Errorf("%w: sync input range exceeds whole-input size", ErrDecode)
		}
	case "nexus.v1.BuilderSyncAttemptV1":
		outcome := scalarAt(fields, 3)
		if outcome == 1 && len(fields[6]) == 0 || outcome == 2 && len(fields[4]) == 0 {
			return fmt.Errorf("%w: accepted/rejected sync attempt lacks its signed outcome", ErrDecode)
		}
	case "nexus.v1.OutputChunkV1":
		if len(bytesAt(fields, 3)) != 32 || len(bytesAt(fields, 4)) != SignatureSize || len(bytesAt(fields, 8)) != 32 || len(bytesAt(fields, 5)) != 0 || len(bytesAt(fields, 6)) != 0 {
			return fmt.Errorf("%w: output chunk commitment, signature or inactive attachment", ErrDecode)
		}
	case "nexus.v1.OutputFinV1":
		if len(bytesAt(fields, 2)) != 32 || len(bytesAt(fields, 4)) != SignatureSize || len(bytesAt(fields, 5)) != 32 || scalarAt(fields, 3) < 1 || scalarAt(fields, 3) > 6 {
			return fmt.Errorf("%w: output Fin commitment, signature or finish reason", ErrDecode)
		}
	case "nexus.v1.BuilderSyncOutputV1":
		if len(fields[4]) > MaxBuilderSyncEntries || len(fields[4]) == 0 && len(fields[5]) == 0 {
			return fmt.Errorf("%w: sync output must contain bounded frames", ErrDecode)
		}
		var previous uint64
		for i, raw := range fields[4] {
			chunk, err := decode("nexus.v1.OutputChunkV1", raw.bytes, 1)
			if err != nil {
				return err
			}
			sequence := scalarAt(chunk, 1)
			if !bytes.Equal(bytesAt(chunk, 8), bytesAt(fields, 1)) || i > 0 && (previous == math.MaxUint64 || sequence != previous+1) {
				return fmt.Errorf("%w: sync output sequence or ticket mismatch", ErrDecode)
			}
			previous = sequence
		}
		if len(fields[5]) != 0 {
			fin, err := decode("nexus.v1.OutputFinV1", bytesAt(fields, 5), 1)
			if err != nil {
				return err
			}
			if !bytes.Equal(bytesAt(fin, 5), bytesAt(fields, 1)) || len(fields[4]) != 0 && scalarAt(fin, 1) != previous {
				return fmt.Errorf("%w: sync Fin sequence or ticket mismatch", ErrDecode)
			}
			if len(fields[4]) != 0 {
				last, err := decode("nexus.v1.OutputChunkV1", fields[4][len(fields[4])-1].bytes, 1)
				if err != nil {
					return err
				}
				if !bytes.Equal(bytesAt(fin, 2), bytesAt(last, 3)) {
					return fmt.Errorf("%w: sync Fin root differs from its last chunk", ErrDecode)
				}
			}
		}
		ticket, err := SigningDigest("task.v1.DispatchTicketV1", bytesAt(fields, 2))
		if err != nil {
			return err
		}
		if !bytes.Equal(ticket[:], bytesAt(fields, 1)) {
			return fmt.Errorf("%w: sync output winner ticket commitment differs", ErrDecode)
		}
	case "nexus.v1.SyncResponse":
		received, sealed, notHeld := scalarAt(fields, 2) != 0, scalarAt(fields, 4) != 0, scalarAt(fields, 6) != 0
		if !received && (scalarAt(fields, 3) != 0 || sealed) || received && notHeld {
			return fmt.Errorf("%w: contradictory sync output acknowledgement", ErrDecode)
		}
	}
	return nil
}

// validateBuilderSyncScopes checks identities available inside one batch. Task
// versions may change under RBF, so task_hash is not frozen for the whole stream.
func validateBuilderSyncScopes(batch decoded) error {
	if len(bytesAt(batch, 5)) != 32 || len(bytesAt(batch, 8)) != 32 {
		return fmt.Errorf("%w: sync Session and BuilderSet must be raw32", ErrDecode)
	}
	task := HashFields("TRUEOPEN_TASK_ID_V1", bytesAt(batch, 5), Uint64(scalarAt(batch, 6)))
	checkDispatch := func(name string, raw []byte) error {
		message, err := decode(name, raw, 1)
		if err != nil {
			return err
		}
		if !bytes.Equal(bytesAt(message, 2), bytesAt(batch, 2)) || !bytes.Equal(bytesAt(message, 3), task[:]) || !bytes.Equal(bytesAt(message, 5), bytesAt(batch, 5)) || scalarAt(message, 6) != scalarAt(batch, 6) || !bytes.Equal(bytesAt(message, 7), bytesAt(batch, 3)) {
			return fmt.Errorf("%w: sync dispatch identity differs from its batch", ErrDecode)
		}
		return nil
	}
	for _, raw := range batch[9] {
		item, err := decode("nexus.v1.BuilderSyncItemV1", raw.bytes, 1)
		if err != nil {
			return err
		}
		switch {
		case len(item[2]) != 0:
			round, err := decode("nexus.v1.BuilderSyncRoundV1", bytesAt(item, 2), 1)
			if err != nil {
				return err
			}
			roster, err := decode("task.v1.DispatchRosterV1", bytesAt(round, 5), 1)
			if err != nil {
				return err
			}
			root, err := decode("task.v1.SignedHandraiseRootV1", bytesAt(round, 7), 1)
			if err != nil {
				return err
			}
			if !bytes.Equal(bytesAt(round, 1), task[:]) || !bytes.Equal(bytesAt(roster, 1), task[:]) || !bytes.Equal(bytesAt(root, 1), bytesAt(batch, 2)) || !bytes.Equal(bytesAt(root, 2), bytesAt(batch, 3)) {
				return fmt.Errorf("%w: sync round identity differs from its batch", ErrDecode)
			}
		case len(item[4]) != 0:
			attempt, err := decode("nexus.v1.BuilderSyncAttemptV1", bytesAt(item, 4), 1)
			if err != nil {
				return err
			}
			if err := checkDispatch("task.v1.DispatchTicketV1", bytesAt(attempt, 1)); err != nil {
				return err
			}
		case len(item[5]) != 0:
			record, err := decode("nexus.v1.BuilderSyncRecordV1", bytesAt(item, 5), 1)
			if err != nil {
				return err
			}
			if err := checkDispatch("task.v1.DispatchRecordV1", bytesAt(record, 1)); err != nil {
				return err
			}
		case len(item[6]) != 0:
			orderItem, err := decode("nexus.v1.BuilderSyncOrderV1", bytesAt(item, 6), 1)
			if err != nil {
				return err
			}
			signed, err := decode("task.v1.SignedOrderV2", bytesAt(orderItem, 1), 1)
			if err != nil {
				return err
			}
			order, err := decode("task.v1.TaskOrderV3", bytesAt(signed, 1), 1)
			if err != nil {
				return err
			}
			header, err := decode("nexus.v1.DispatchResultHeaderV1", bytesAt(orderItem, 2), 1)
			if err != nil {
				return err
			}
			if !bytes.Equal(bytesAt(order, 2), bytesAt(batch, 2)) || !bytes.Equal(bytesAt(order, 4), bytesAt(batch, 5)) || scalarAt(order, 5) != scalarAt(batch, 6) || !bytes.Equal(bytesAt(order, 24), bytesAt(batch, 7)) || !bytes.Equal(bytesAt(order, 25), bytesAt(batch, 8)) || !bytes.Equal(bytesAt(header, 1), task[:]) || scalarAt(header, 4) != 2 {
				return fmt.Errorf("%w: sync order identity or recorded status differs", ErrDecode)
			}
			if err := checkDispatch("task.v1.DispatchTicketV1", bytesAt(header, 2)); err != nil {
				return err
			}
		}
	}
	if len(batch[10]) != 0 {
		output, err := decode("nexus.v1.BuilderSyncOutputV1", bytesAt(batch, 10), 1)
		if err != nil {
			return err
		}
		if err := checkDispatch("task.v1.DispatchTicketV1", bytesAt(output, 2)); err != nil {
			return err
		}
	}
	return nil
}

// VerifyBuilderSyncRequest authenticates the current live transport identity,
// chain and exact receiving operator. The consumer additionally checks immutable
// group membership, business proofs, durable sequencing and chain admission.
// Revoked and retired keys cannot authenticate this live RPC.
func VerifyBuilderSyncRequest(chainID, receiver string, raw []byte, opts ProofKeyOptions) error {
	request, err := decode("nexus.v1.SyncRequest", raw, 0)
	if err != nil {
		return err
	}
	batch, err := decode("nexus.v1.BuilderSyncBatchV1", bytesAt(request, 1), 1)
	if err != nil {
		return err
	}
	if chainID == "" || string(bytesAt(batch, 2)) != chainID || string(bytesAt(batch, 4)) != receiver {
		return fmt.Errorf("%w: sync chain or receiver mismatch", ErrEvidence)
	}
	if _, err := AddressBytes(receiver); err != nil {
		return err
	}
	digest, err := SigningDigest("nexus.v1.SyncRequest", raw)
	if err != nil {
		return err
	}
	key, err := verifyServiceProofSignature(ServiceProofSigner{ParticipantType: ProofParticipantBuilder, OperatorAddress: string(bytesAt(batch, 3))}, digest, bytesAt(request, 2), opts)
	if err != nil {
		return err
	}
	if key.Status != ProofKeyActive {
		return fmt.Errorf("%w: sync requires current ACTIVE transport authority", ErrProofKeyUnavailable)
	}
	return nil
}
