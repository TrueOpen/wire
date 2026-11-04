package dispatch

import (
	"fmt"
)

// ValuePositionOpening retains the exact canonical leaves and their proof paths.
// Membership and local metric predicates require accepted Task/Profile authority.
type ValuePositionOpening struct {
	Position                             uint64
	WorkerLeaf, VerifierLeaf, MetricLeaf []byte
	WorkerPath, VerifierPath, MetricPath [][32]byte
}

// ValueEvidence is bounded plain proof material, not a stored receipt or a fault.
type ValueEvidence struct {
	TaskID            [32]byte
	VerifyRound       uint32
	TargetOperator    string
	Kind              uint32
	WorkerRoot        [32]byte
	WorkerEncodedSize uint64
	Positions         []ValuePositionOpening
}

func scalarAt(d decoded, field uint32) uint64 {
	if len(d[field]) == 0 {
		return 0
	}
	return d[field][0].varint
}

func bytesAt(d decoded, field uint32) []byte {
	if len(d[field]) == 0 {
		return nil
	}
	return append([]byte(nil), d[field][0].bytes...)
}

func hashesAt(d decoded, field uint32) ([][32]byte, error) {
	out := make([][32]byte, len(d[field]))
	for i, v := range d[field] {
		if len(v.bytes) != 32 {
			return nil, fmt.Errorf("%w: proof node requires raw32", ErrDecode)
		}
		copy(out[i][:], v.bytes)
	}
	return out, nil
}

// DecodeValueEvidence checks the exact protobuf subtree before returning plain
// material. Governance caps are additional to the canonical message hard cap.
// It neither decides fault nor substitutes for commitment/Task authority checks.
func DecodeValueEvidence(raw []byte, maxBytes uint64, maxPositions uint32) (ValueEvidence, error) {
	var out ValueEvidence
	if len(raw) == 0 || uint64(len(raw)) > maxBytes || maxPositions == 0 {
		return out, fmt.Errorf("%w: value evidence limits", ErrDecode)
	}
	d, err := decode("task.v1.VerifierValueEvidenceV1", raw, 0)
	if err != nil {
		return out, err
	}
	if scalarAt(d, 1) != 1 || scalarAt(d, 3) == 0 || scalarAt(d, 5) == 0 || len(d[4]) != 1 || len(d[6]) != 1 || len(d[7]) == 0 || uint64(len(d[7])) > uint64(maxPositions) {
		return out, fmt.Errorf("%w: incomplete value evidence", ErrDecode)
	}
	out.TaskID, err = hashAt(d, 2)
	if err != nil {
		return out, err
	}
	out.VerifyRound = uint32(scalarAt(d, 3))
	out.TargetOperator = string(d[4][0].bytes)
	if _, err = AddressBytes(out.TargetOperator); err != nil {
		return out, err
	}
	out.Kind = uint32(scalarAt(d, 5))
	opening, err := decode("task.v1.WorkerValueCommitmentOpeningV1", d[6][0].bytes, 1)
	if err != nil {
		return out, err
	}
	out.WorkerRoot, err = hashAt(opening, 1)
	if err != nil {
		return out, err
	}
	out.WorkerEncodedSize = scalarAt(opening, 2)
	if out.WorkerEncodedSize == 0 {
		return out, fmt.Errorf("%w: empty Worker commitment", ErrDecode)
	}
	for _, entry := range d[7] {
		p, err := decode("task.v1.VerifierValuePositionOpeningV1", entry.bytes, 1)
		if err != nil {
			return out, err
		}
		position := ValuePositionOpening{Position: scalarAt(p, 1), WorkerLeaf: bytesAt(p, 2), VerifierLeaf: bytesAt(p, 4), MetricLeaf: bytesAt(p, 6)}
		if position.WorkerPath, err = hashesAt(p, 3); err != nil {
			return out, err
		}
		if position.VerifierPath, err = hashesAt(p, 5); err != nil {
			return out, err
		}
		if position.MetricPath, err = hashesAt(p, 7); err != nil {
			return out, err
		}
		if len(position.WorkerLeaf) == 0 || len(out.Positions) > 0 && out.Positions[len(out.Positions)-1].Position >= position.Position {
			return out, fmt.Errorf("%w: missing or unordered position", ErrDecode)
		}
		if out.Kind == 1 && (len(position.VerifierLeaf) == 0 || len(position.MetricLeaf) == 0) || out.Kind == 2 && (len(position.VerifierLeaf)+len(position.VerifierPath)+len(position.MetricLeaf)+len(position.MetricPath) != 0) {
			return out, fmt.Errorf("%w: proof branch does not match evidence kind", ErrDecode)
		}
		out.Positions = append(out.Positions, position)
	}
	return out, nil
}

// ValueEvidenceDigest commits semantic leaf hashes, excluding membership paths
// and the transaction submitter. The caller supplies its authoritative chain.
// All three active canonical leaf schemas use leaf_version=1.
func ValueEvidenceDigest(chainID string, raw []byte, maxBytes uint64, maxPositions uint32) ([32]byte, error) {
	evidence, err := DecodeValueEvidence(raw, maxBytes, maxPositions)
	if err != nil {
		return [32]byte{}, err
	}
	if chainID == "" {
		return [32]byte{}, fmt.Errorf("%w: missing chain", ErrDecode)
	}
	operator, err := AddressBytes(evidence.TargetOperator)
	if err != nil {
		return [32]byte{}, err
	}
	positions := [][]byte{Uint32(uint32(len(evidence.Positions)))}
	for _, position := range evidence.Positions {
		worker := HashFields("TRUEOPEN_PREFILL_WORKER_VALUE_LEAF_V1", Uint32(1), position.WorkerLeaf)
		var verifier, metric [32]byte
		if evidence.Kind == 1 {
			verifier = HashFields("TRUEOPEN_PREFILL_VERIFIER_VALUE_LEAF_V1", Uint32(1), position.VerifierLeaf)
			metric = HashFields("TRUEOPEN_PREFILL_TOKEN_METRIC_LEAF_V3", Uint32(1), position.MetricLeaf)
		}
		positions = append(positions, FieldFrame(Uint64(position.Position), worker[:], verifier[:], metric[:]))
	}
	return HashFields("TRUEOPEN_VERIFIER_VALUE_EVIDENCE_V1", Uint32(1), []byte(chainID), evidence.TaskID[:], Uint32(evidence.VerifyRound), operator, Uint32(evidence.Kind), Uint32(uint32(len(evidence.Positions))), FieldFrame(positions...)), nil
}
