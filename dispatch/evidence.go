package dispatch

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Domains of the Builder objective-evidence identity chain, registered in
// registry/v1/domains.json and defined once. All three
// retain their generation for the fresh-genesis typed-message projection.
// Old transport-envelope vectors are retired.
const (
	EvidenceContentDomain = "TRUEOPEN_BUILDER_EVIDENCE_CONTENT_V2"
	EvidenceIDDomain      = "TRUEOPEN_BUILDER_EVIDENCE_ID_V2"
	BuilderFaultDomain    = "TRUEOPEN_BUILDER_FAULT_V2"
)

// Oneof tags of BuilderEvidenceV2. The retired missed-duty tag 4 stays reserved.
const (
	EvidenceTagEquivocation           uint32 = 2
	EvidenceTagInvalidStageSubmission uint32 = 3
	EvidenceTagDataUnavailable        uint32 = 5
)

// BuilderEvidenceKind values, mirrored value-for-value by BuilderFaultKind.
const (
	EvidenceKindUnspecified              int32 = 0
	EvidenceKindProposalEquivocation     int32 = 1
	EvidenceKindInvalidStageSubmission   int32 = 2
	EvidenceKindObjectiveDataUnavailable int32 = 4
)

// evidenceSchemaVersion is BuilderEvidenceV2.schema_version, which is a fixed 2
// and enters the content preimage as its first field.
const evidenceSchemaVersion uint32 = 2

// ErrEvidence classifies a rejection that is about the evidence rather than
// about malformed bytes. The distinction matters for attribution: malformed
// material is nobody's fault, whereas a well-formed message that fails a scope
// check is a claim about a specific Builder.
var ErrEvidence = errors.New("dispatch: builder evidence")

// evidenceTagKind is the one-to-one oneof-tag to kind mapping. Keeping it as a
// table rather than a switch means a new tag cannot be added without deciding
// which kind it attributes to.
var evidenceTagKind = map[uint32]int32{
	EvidenceTagEquivocation:           EvidenceKindProposalEquivocation,
	EvidenceTagInvalidStageSubmission: EvidenceKindInvalidStageSubmission,
	EvidenceTagDataUnavailable:        EvidenceKindObjectiveDataUnavailable,
}

// EquivocationContent is the tag 2 canonical content: the two signing digests of
// the conflicting envelopes.
type EquivocationContent struct {
	MessageKind int32
	DigestA     []byte
	DigestB     []byte
}

// BuilderProtocolViolation values mirror the frozen enum. Only values 1 and 2
// are ACTIVE in V1. Values 3..6 retain their wire numbers but fail closed until
// a future typed evidence schema freezes their authority predicates.
const (
	ViolationWrongTaskScope              int32 = 1
	ViolationWrongStage                  int32 = 2
	ViolationWrongBuilderSet             int32 = 3
	ViolationNonCanonicalBitmap          int32 = 4
	ViolationBitClearAttempt             int32 = 5
	ViolationConflictingAcceptedMaterial int32 = 6

	maxBuilderProtocolViolation int32 = ViolationConflictingAcceptedMaterial
)

// IsActiveBuilderProtocolViolation reports whether a violation may be applied
// by the current BuilderEvidenceV2 invalid-stage branch.
func IsActiveBuilderProtocolViolation(violation int32) bool {
	return violation == ViolationWrongTaskScope || violation == ViolationWrongStage
}

// ValidateActiveBuilderProtocolViolation fails closed for unspecified, unknown,
// and reserved non-ACTIVE violation values. Callers map this authority failure to
// FailedPrecondition and perform no writes.
func ValidateActiveBuilderProtocolViolation(violation int32) error {
	if IsActiveBuilderProtocolViolation(violation) {
		return nil
	}
	if violation >= ViolationWrongBuilderSet && violation <= maxBuilderProtocolViolation {
		return fmt.Errorf("%w: BuilderProtocolViolation %d is reserved but NON_ACTIVE in V1",
			ErrEvidence, violation)
	}
	return fmt.Errorf("%w: violation %d is not an active BuilderProtocolViolation",
		ErrEvidence, violation)
}

// InvalidStageContent is the tag 3 canonical content.
type InvalidStageContent struct {
	MessageKind   int32
	SigningDigest []byte
	Violation     int32
}

// DataUnavailableContent is the tag 5 canonical content: stable round-1
// primary keys only. Deadlines, accepted versions, report hashes, counts,
// thresholds and the verdict are all loaded and recomputed by the Keeper and
// never submitted.
type DataUnavailableContent struct {
	TaskID          []byte
	VerifyRound     uint32
	BuilderOperator string
}

// EquivocationDigest is canonical_evidence_digest for tag 2.
//
// The two signing digests are ordered by ascending lexicographic bytes, so one
// equivocation has one identity whichever message the submitter happened to
// send first. The raw signatures are absent by design: they are proof only, and
// two valid low-S signatures over one message signing digest have to derive the same
// evidence identity.
func EquivocationDigest(content EquivocationContent) ([32]byte, error) {
	if content.MessageKind != 1 && content.MessageKind != 2 {
		return [32]byte{}, fmt.Errorf("%w: inactive message kind", ErrEvidence)
	}
	if len(content.DigestA) != 32 || len(content.DigestB) != 32 {
		return [32]byte{}, fmt.Errorf("%w: equivocation needs two raw32 signing digests", ErrEvidence)
	}
	if bytes.Equal(content.DigestA, content.DigestB) {
		return [32]byte{}, fmt.Errorf("%w: equivocation needs two different signing digests", ErrEvidence)
	}
	lower, higher := content.DigestA, content.DigestB
	if bytes.Compare(lower, higher) > 0 {
		lower, higher = higher, lower
	}
	return contentDigest(EvidenceTagEquivocation, Uint32(uint32(content.MessageKind)), lower, higher), nil
}

// InvalidStageDigest is canonical_evidence_digest for tag 3.
func InvalidStageDigest(content InvalidStageContent) ([32]byte, error) {
	if content.MessageKind != 1 && content.MessageKind != 2 {
		return [32]byte{}, fmt.Errorf("%w: inactive message kind", ErrEvidence)
	}
	if len(content.SigningDigest) != 32 {
		return [32]byte{}, fmt.Errorf("%w: invalid stage submission needs a raw32 signing digest", ErrEvidence)
	}
	if err := ValidateActiveBuilderProtocolViolation(content.Violation); err != nil {
		return [32]byte{}, err
	}
	return contentDigest(EvidenceTagInvalidStageSubmission, Uint32(uint32(content.MessageKind)), content.SigningDigest, Uint32(uint32(content.Violation))), nil
}

// DataUnavailableDigest is canonical_evidence_digest for tag 5.
func DataUnavailableDigest(content DataUnavailableContent) ([32]byte, error) {
	if len(content.TaskID) != 32 {
		return [32]byte{}, fmt.Errorf("%w: data unavailable needs a raw32 task_id", ErrEvidence)
	}
	if content.VerifyRound != 1 {
		return [32]byte{}, fmt.Errorf("%w: data unavailable tag 5 requires verify_round 1, got %d",
			ErrEvidence, content.VerifyRound)
	}
	operator, err := AddressBytes(content.BuilderOperator)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: builder_operator: %v", ErrEvidence, err)
	}
	return contentDigest(EvidenceTagDataUnavailable,
		content.TaskID, Uint32(content.VerifyRound), operator), nil
}

// contentDigest builds the shared head of every branch: schema_version and the
// oneof tag, both u32be, followed by the branch's canonical selected fields.
func contentDigest(tag uint32, selected ...[]byte) [32]byte {
	parts := make([][]byte, 0, len(selected)+3)
	parts = append(parts, []byte(EvidenceContentDomain), Uint32(evidenceSchemaVersion), Uint32(tag))
	parts = append(parts, selected...)
	return sha256.Sum256(FieldFrame(parts...))
}

// EvidenceID is the MsgSubmitBuilderEvidence idempotency key.
//
// FaultID below has an identical field list and differs only in the domain
// literal. That is deliberate, not duplication: evidence_id keys the submission
// and fault_id keys the punishable fact derived from it, and this contract requires the
// two to stay distinct values that never substitute for each other.
func EvidenceID(chainID, builderOperator string, evidenceKind int32, scopeID []byte, contentDigest [32]byte) ([32]byte, error) {
	return identityDigest(EvidenceIDDomain, chainID, builderOperator, evidenceKind, scopeID, contentDigest)
}

// FaultID is the primary key of the punishable fact.
func FaultID(chainID, builderOperator string, evidenceKind int32, scopeID []byte, contentDigest [32]byte) ([32]byte, error) {
	return identityDigest(BuilderFaultDomain, chainID, builderOperator, evidenceKind, scopeID, contentDigest)
}

func identityDigest(domain, chainID, builderOperator string, evidenceKind int32, scopeID []byte, content [32]byte) ([32]byte, error) {
	if chainID == "" {
		return [32]byte{}, fmt.Errorf("%w: chain_id is required", ErrEvidence)
	}
	operator, err := AddressBytes(builderOperator)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: builder_operator: %v", ErrEvidence, err)
	}
	if err := checkEvidenceKind(evidenceKind); err != nil {
		return [32]byte{}, err
	}
	// scope_id is the existing authoritative primary key of the attributed fact -
	// task_id for all three active kinds - and never a newly invented hash.
	if len(scopeID) != 32 {
		return [32]byte{}, fmt.Errorf("%w: scope_id must be raw32", ErrEvidence)
	}
	return sha256.Sum256(FieldFrame(
		[]byte(domain),
		[]byte(chainID),
		operator,
		Uint32(uint32(evidenceKind)),
		scopeID,
		content[:],
	)), nil
}

// checkEvidenceKind permits only the three attributable public evidence kinds.
func checkEvidenceKind(kind int32) error {
	switch kind {
	case EvidenceKindProposalEquivocation, EvidenceKindInvalidStageSubmission, EvidenceKindObjectiveDataUnavailable:
		return nil
	default:
		return fmt.Errorf("%w: evidence_kind %d is inactive", ErrEvidence, kind)
	}
}

// EvidenceKindForTag maps a BuilderEvidenceV2 oneof tag to its evidence kind.
// Tag 4 is absent, so an attempt to attribute the reserved branch fails here
// rather than reaching the fault kernel.
func EvidenceKindForTag(tag uint32) (int32, error) {
	kind, ok := evidenceTagKind[tag]
	if !ok {
		return 0, fmt.Errorf("%w: oneof tag %d is not an active evidence branch", ErrEvidence, tag)
	}
	return kind, nil
}
