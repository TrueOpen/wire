package bus

import "fmt"

// BuilderEvidenceSchemaVersionV2 is the only schema version accepted by the
// public Builder objective-evidence wire.
const BuilderEvidenceSchemaVersionV2 uint32 = 2

// MaxBuilderEvidenceBytesV2 bounds the exact serialized BuilderEvidenceV2
// carried by MsgSubmitBuilderEvidence.evidence_bytes.
const MaxBuilderEvidenceBytesV2 = 2_100_000

// DecodedBuilderEvidenceV2 is a strict, generated-code-free projection of one
// exact serialized task.v1.BuilderEvidenceV2. Exactly one branch is set.
type DecodedBuilderEvidenceV2 struct {
	SchemaVersion          uint32
	EvidenceTag            uint32
	Equivocation           *SignedEnvelopeEquivocationV2
	InvalidStageSubmission *SignedEnvelopeProtocolFaultV2
	DataUnavailable        *DataUnavailableStateReferenceV1
}

// SignedEnvelopeEquivocationV2 carries the exact bytes of the two envelopes.
// Callers verify both with VerifyEvidenceEnvelope and then apply Task authority
// plus EquivocationPreconditions; this decoder never re-marshals either value.
type SignedEnvelopeEquivocationV2 struct {
	EnvelopeA []byte
	EnvelopeB []byte
}

// SignedEnvelopeProtocolFaultV2 carries one exact envelope and the caller's
// closed violation claim. Callers verify the envelope with
// VerifyEvidenceEnvelope, then prove the violation against Task authority.
type SignedEnvelopeProtocolFaultV2 struct {
	Envelope  []byte
	Violation int32
}

// DataUnavailableStateReferenceV1 contains only stable primary-key fields.
// Wire requires verify_round=1. The Task caller must additionally require an
// actual data-ready attester, a CONFIRMED aggregate, and the settlement/finality
// timing fixed by the protocol contract.
type DataUnavailableStateReferenceV1 struct {
	TaskID          []byte
	VerifyRound     uint32
	BuilderOperator string
}

// DecodeBuilderEvidenceV2 strictly decodes exact BuilderEvidenceV2 bytes
// without importing generated Hub, Task or Bus packages.
//
// It rejects unknown and reserved fields, duplicate singular fields, duplicate
// oneof branches, wrong wire types, groups, non-minimal varints, missing or
// empty branches, and malformed branch-local required fields. It deliberately
// does not consult Task state. Tag 5's fixed normal-round value is checked here;
// its Task-state authority and tag 3 violation authority remain caller checks.
func DecodeBuilderEvidenceV2(raw []byte) (DecodedBuilderEvidenceV2, error) {
	if len(raw) == 0 || len(raw) > MaxBuilderEvidenceBytesV2 {
		return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: BuilderEvidenceV2 size must be 1..%d bytes, got %d",
			ErrDecode, MaxBuilderEvidenceBytesV2, len(raw))
	}

	message, err := strictDecodeWithLimit(msgBuilderEvidenceV2, raw, MaxBuilderEvidenceBytesV2)
	if err != nil {
		return DecodedBuilderEvidenceV2{}, err
	}
	schemaVersion, err := message.uint32At(msgBuilderEvidenceV2, 1)
	if err != nil {
		return DecodedBuilderEvidenceV2{}, err
	}
	if schemaVersion != BuilderEvidenceSchemaVersionV2 {
		return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: BuilderEvidenceV2.schema_version is %d, want %d",
			ErrDecode, schemaVersion, BuilderEvidenceSchemaVersionV2)
	}

	var tag uint32
	for _, candidate := range []uint32{
		EvidenceTagEquivocation,
		EvidenceTagInvalidStageSubmission,
		EvidenceTagDataUnavailable,
	} {
		if !message.has(candidate) {
			continue
		}
		if tag != 0 {
			return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: BuilderEvidenceV2 oneof has both fields %d and %d",
				ErrDecode, tag, candidate)
		}
		tag = candidate
	}
	if tag == 0 {
		return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: BuilderEvidenceV2 must contain exactly one active evidence branch",
			ErrDecode)
	}
	branch := message.bytesAt(tag)
	if len(branch) == 0 {
		return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: BuilderEvidenceV2 branch field %d is empty", ErrDecode, tag)
	}

	out := DecodedBuilderEvidenceV2{SchemaVersion: schemaVersion, EvidenceTag: tag}
	switch tag {
	case EvidenceTagEquivocation:
		decoded, err := strictDecodeWithLimit(msgSignedEnvelopeEquivocationV2, branch, MaxBuilderEvidenceBytesV2)
		if err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		envelopeA := decoded.bytesAt(1)
		envelopeB := decoded.bytesAt(2)
		if err := requireEvidenceEnvelope("envelope_a", envelopeA); err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		if err := requireEvidenceEnvelope("envelope_b", envelopeB); err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		out.Equivocation = &SignedEnvelopeEquivocationV2{EnvelopeA: envelopeA, EnvelopeB: envelopeB}

	case EvidenceTagInvalidStageSubmission:
		decoded, err := strictDecodeWithLimit(msgSignedEnvelopeProtocolFaultV2, branch, MaxBuilderEvidenceBytesV2)
		if err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		envelope := decoded.bytesAt(1)
		if err := requireEvidenceEnvelope("envelope", envelope); err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		violation, err := decoded.int32At(msgSignedEnvelopeProtocolFaultV2, 2)
		if err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		out.InvalidStageSubmission = &SignedEnvelopeProtocolFaultV2{
			Envelope: envelope, Violation: violation,
		}

	case EvidenceTagDataUnavailable:
		decoded, err := strictDecodeWithLimit(msgDataUnavailableStateReferenceV1, branch, MaxBuilderEvidenceBytesV2)
		if err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		taskID, err := decoded.hash32At(msgDataUnavailableStateReferenceV1, 1)
		if err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		verifyRound, err := decoded.uint32At(msgDataUnavailableStateReferenceV1, 2)
		if err != nil {
			return DecodedBuilderEvidenceV2{}, err
		}
		if verifyRound != 1 {
			return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: DataUnavailableStateReferenceV1.verify_round is %d, want 1",
				ErrDecode, verifyRound)
		}
		builderOperator := decoded.stringAt(3)
		if builderOperator == "" {
			return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: DataUnavailableStateReferenceV1.builder_operator is required",
				ErrDecode)
		}
		if _, err := operatorAddressCodecBytesForHRP(builderOperator, OperatorAddressHRPV1); err != nil {
			return DecodedBuilderEvidenceV2{}, fmt.Errorf("%w: DataUnavailableStateReferenceV1.builder_operator: %v",
				ErrDecode, err)
		}
		out.DataUnavailable = &DataUnavailableStateReferenceV1{
			TaskID: taskID, VerifyRound: verifyRound, BuilderOperator: builderOperator,
		}
	}
	return out, nil
}

func requireEvidenceEnvelope(field string, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return fmt.Errorf("%w: %s must contain 1..%d exact BusEnvelopeV1 bytes, got %d",
			ErrDecode, field, MaxEnvelopeBytes, len(raw))
	}
	return nil
}
