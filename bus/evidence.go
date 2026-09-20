package bus

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Domains of the Builder objective-evidence identity chain, registered in
// registry/v1/domains.json and defined once in keeper_api_contract.md §5.5. All three
// are V2 because the BusEnvelope V2 cutover changed the nested evidence schema,
// the kind numbers and the signing rule, and canonical_encoding_and_domain_hashing.md §7 forbids
// reinterpreting a domain rather than replacing it.
const (
	EvidenceContentDomain = "TRUEOPEN_BUILDER_EVIDENCE_CONTENT_V2"
	EvidenceIDDomain      = "TRUEOPEN_BUILDER_EVIDENCE_ID_V2"
	BuilderFaultDomain    = "TRUEOPEN_BUILDER_FAULT_V2"
)

// Oneof tags of task.v1.BuilderEvidenceV2. Tag 4 is permanently reserved:
// OBJECTIVE_MISSED_DUTY stays a Keeper-internal derivation from an authoritative
// duty receipt, so the old public branch is never reused and a future public
// wire takes a new tag.
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
	EvidenceKindObjectiveMissedDuty      int32 = 3
	EvidenceKindObjectiveDataUnavailable int32 = 4
)

// evidenceSchemaVersion is BuilderEvidenceV2.schema_version, which is a fixed 2
// and enters the content preimage as its first field.
const evidenceSchemaVersion uint32 = BuilderEvidenceSchemaVersionV2

// ErrEvidence classifies a rejection that is about the evidence rather than
// about malformed bytes. The distinction matters for attribution: malformed
// material is nobody's fault, whereas a well-formed envelope that fails a scope
// check is a claim about a specific Builder.
var ErrEvidence = errors.New("bus: builder evidence")

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
	DigestA []byte
	DigestB []byte
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
// equivocation has one identity whichever envelope the submitter happened to
// send first. The raw signatures are absent by design: they are proof only, and
// two valid low-S signatures over one bus_signing_digest have to derive the same
// evidence identity.
func EquivocationDigest(content EquivocationContent) ([32]byte, error) {
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
	return contentDigest(EvidenceTagEquivocation, lower, higher), nil
}

// InvalidStageDigest is canonical_evidence_digest for tag 3.
func InvalidStageDigest(content InvalidStageContent) ([32]byte, error) {
	if len(content.SigningDigest) != 32 {
		return [32]byte{}, fmt.Errorf("%w: invalid stage submission needs a raw32 signing digest", ErrEvidence)
	}
	if err := ValidateActiveBuilderProtocolViolation(content.Violation); err != nil {
		return [32]byte{}, err
	}
	return contentDigest(EvidenceTagInvalidStageSubmission, content.SigningDigest, u32be(uint32(content.Violation))), nil
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
	operator, err := operatorAddressCodecBytesForHRP(content.BuilderOperator, OperatorAddressHRPV1)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: builder_operator: %v", ErrEvidence, err)
	}
	return contentDigest(EvidenceTagDataUnavailable,
		content.TaskID, u32be(content.VerifyRound), operator), nil
}

// contentDigest builds the shared head of every branch: schema_version and the
// oneof tag, both u32be, followed by the branch's canonical selected fields.
func contentDigest(tag uint32, selected ...[]byte) [32]byte {
	parts := make([][]byte, 0, len(selected)+3)
	parts = append(parts, []byte(EvidenceContentDomain), u32be(evidenceSchemaVersion), u32be(tag))
	parts = append(parts, selected...)
	return sha256.Sum256(frame(parts...))
}

// EvidenceID is the MsgSubmitBuilderEvidence idempotency key.
//
// FaultID below has an identical field list and differs only in the domain
// literal. That is deliberate, not duplication: evidence_id keys the submission
// and fault_id keys the punishable fact derived from it, and §5.5 requires the
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
	operator, err := operatorAddressCodecBytesForHRP(builderOperator, OperatorAddressHRPV1)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: builder_operator: %v", ErrEvidence, err)
	}
	if err := checkEvidenceKind(domain, evidenceKind); err != nil {
		return [32]byte{}, err
	}
	// scope_id is the existing authoritative primary key of the attributed fact -
	// task_id for all three active kinds - and never a newly invented hash.
	if len(scopeID) != 32 {
		return [32]byte{}, fmt.Errorf("%w: scope_id must be raw32", ErrEvidence)
	}
	return sha256.Sum256(frame(
		[]byte(domain),
		[]byte(chainID),
		operator,
		u32be(uint32(evidenceKind)),
		scopeID,
		content[:],
	)), nil
}

// checkEvidenceKind applies a different whitelist per domain.
//
// A fault may be recorded for any of the four kinds, including
// OBJECTIVE_MISSED_DUTY, which the Keeper derives internally from an
// authoritative duty receipt. An evidence_id may not: it keys a
// MsgSubmitBuilderEvidence submission, BuilderEvidenceV2 oneof tag 4 is
// permanently reserved, and so no public submission can carry that kind. Sharing
// one whitelist would mint an idempotency key for a message that cannot exist.
func checkEvidenceKind(domain string, kind int32) error {
	switch kind {
	case EvidenceKindProposalEquivocation, EvidenceKindInvalidStageSubmission,
		EvidenceKindObjectiveDataUnavailable:
		return nil
	case EvidenceKindObjectiveMissedDuty:
		if domain == BuilderFaultDomain {
			return nil
		}
		return fmt.Errorf("%w: OBJECTIVE_MISSED_DUTY is Keeper-derived and has no public evidence submission, "+
			"so it has no %s", ErrEvidence, domain)
	default:
		return fmt.Errorf("%w: evidence_kind %d is not a known non-zero kind", ErrEvidence, kind)
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

// ProofKeyStatus is the service-key binding status an evidence verifier accepts.
type ProofKeyStatus uint8

const (
	// ProofKeyActive is a live binding.
	ProofKeyActive ProofKeyStatus = iota
	// ProofKeyRevoked is a binding revoked at the same authorization nonce. It
	// remains usable as a historical proof key - an emergency revoke must not
	// destroy the ability to prove what the key already signed - but it
	// authorizes no new envelope or Tx.
	ProofKeyRevoked
)

// ProofKeyLookup resolves the service-key binding an evidence proof is verified
// against. It is looked up by the exact (participant type, operator,
// authorization nonce) triple the envelope names: once the operator has rotated
// to a new nonce or key, the material is stable and the verifier fails closed.
type ProofKeyLookup func(participantType int32, operatorAddress string, authorizationNonce uint64) (publicKey []byte, status ProofKeyStatus, err error)

// EvidenceVerifyOptions configures the chain proof-only profile.
//
// There is deliberately no clock and no replay store here. Both are in
// VerifyOptions for the live receiver, and keeper_api_contract.md §5.5 is explicit
// that the chain profile has neither: expires_at bounds live transport delivery
// only, so rejecting an already-signed objective fact by current wall clock
// would let a Builder outlive its own evidence. Exact replay is done by the
// outer canonical evidence ID, never against the Bus live replay store.
type EvidenceVerifyOptions struct {
	// ChainID is the local chain. A cross-chain envelope is not evidence here.
	ChainID string
	// LookupKey resolves the proof key. Required.
	LookupKey ProofKeyLookup
}

// VerifiedEvidenceEnvelope is one envelope that passed the proof-only profile.
type VerifiedEvidenceEnvelope struct {
	DecodedEnvelope
	// SigningDigest is the value the signature was verified against and the value
	// the canonical evidence content commits to.
	SigningDigest [32]byte
}

// VerifyEvidenceEnvelope runs the chain proof-only profile of
// keeper_api_contract.md §5.5 over one exact serialized BusEnvelopeV1.
//
// The order matters and is the document's: size and strict structure, then
// schema and chain and kind and the fixed TTL bound, then the payload digest
// over the exact bytes, then the proof key, then the signature, then the typed
// payload and the derived subject. Nothing after the signature check is reached
// by unsigned material, and nothing before it depends on Task state.
//
// The caller still owes the two steps this package cannot do: comparing the
// returned scope against Task, BuilderSet and stage authority, and exact replay
// on the outer evidence ID.
func VerifyEvidenceEnvelope(raw []byte, opts EvidenceVerifyOptions) (VerifiedEvidenceEnvelope, error) {
	if opts.LookupKey == nil {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: LookupKey is required", ErrEvidence)
	}
	if opts.ChainID == "" {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: ChainID is required", ErrEvidence)
	}

	// Steps 1 and 3: strict decode of the envelope with unknown-field rejection,
	// and the payload digest recomputed over the exact received bytes. The typed
	// payload is deliberately NOT decoded yet - that is step 6, after the
	// signature - so that a malformed payload inside a validly signed envelope is
	// reported as attributable evidence rather than as anonymous malformed input.
	envelope, err := DecodeEnvelopeHeader(raw)
	if err != nil {
		return VerifiedEvidenceEnvelope{}, err
	}
	fields := envelope.Fields

	// Step 2: schema, local chain, known kind and payload type, and the TTL bound
	// as a protocol constant. No validator-local TTL configuration is consulted.
	if fields.SchemaVersion != SchemaVersion {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: schema_version %d, want %d",
			ErrEvidence, fields.SchemaVersion, SchemaVersion)
	}
	if fields.ChainID != opts.ChainID {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: envelope chain_id %q is not the local chain %q",
			ErrEvidence, fields.ChainID, opts.ChainID)
	}
	if fields.IssuedAtUnixMS == 0 || fields.ExpiresAtUnixMS <= fields.IssuedAtUnixMS {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: issued_at must be positive and below expires_at", ErrEvidence)
	}
	if fields.ExpiresAtUnixMS-fields.IssuedAtUnixMS > MaxEnvelopeTTLMS {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: ttl exceeds the %dms protocol constant",
			ErrEvidence, MaxEnvelopeTTLMS)
	}

	// Step 4: reject a non-current or non-canonical HRP before any key lookup.
	// The address codec bytes remain the only address material in every digest;
	// this is an acceptance gate, not a signing-preimage change.
	if _, err := operatorAddressCodecBytesForHRP(fields.SenderOperatorAddress, OperatorAddressHRPV1); err != nil {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: sender_operator_address: %v", ErrEvidence, err)
	}

	// The proof key is read at the exact authorization nonce the envelope
	// names. A revoked binding at that same nonce is still a valid historical
	// proof key; a rotation to a new nonce or key fails closed.
	publicKey, status, err := opts.LookupKey(fields.SenderParticipantType, fields.SenderOperatorAddress,
		fields.ServiceAuthorizationNonce)
	if err != nil {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: proof key lookup: %v", ErrEvidence, err)
	}
	if status != ProofKeyActive && status != ProofKeyRevoked {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: proof key status %d is not usable", ErrEvidence, status)
	}

	// Step 5: direct-digest compact low-S signature over bus_signing_digest.
	digest, err := SigningDigest(fields)
	if err != nil {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: %v", ErrEvidence, err)
	}
	if err := VerifyDigestSignature(publicKey, digest[:], envelope.Signature); err != nil {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: %v", ErrEvidence, err)
	}

	// Step 6: only now is the typed payload decoded and projected. A failure here
	// is wrapped in ErrEvidence rather than surfaced as ErrDecode, because the
	// material has a verified signature over it and is therefore attributable to
	// the sender - unlike anything rejected before step 5.
	scope, orderBytes, err := envelope.ProjectPayload()
	if err != nil {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: signed payload does not project to an action scope: %v",
			ErrEvidence, err)
	}
	envelope.Scope = scope
	envelope.OrderBytes = orderBytes

	// The subject derived from the typed payload has to be the subject that was
	// signed. The signed subject is compared against the derived one rather than
	// parsed, so a subject the payload cannot produce is rejected even though it
	// is inside the signature.
	if fields.Subject != scope.ExpectedSubject {
		return VerifiedEvidenceEnvelope{}, fmt.Errorf("%w: signed subject %q does not match the subject derived from the payload, %q",
			ErrEvidence, fields.Subject, scope.ExpectedSubject)
	}

	return VerifiedEvidenceEnvelope{DecodedEnvelope: envelope, SigningDigest: digest}, nil
}

// EquivocationPreconditions checks what makes two verified envelopes one
// equivocation rather than two unrelated messages, per keeper_api_contract.md §5.5:
// identical chain, subject, kind, sender, authorization nonce, message_id,
// payload_type, expiry and payload-derived action scope, but different signing
// digests - which is exactly the dual-key live replay conflict.
//
// Both envelopes must already have passed VerifyEvidenceEnvelope; this compares
// them and does not re-verify either.
func EquivocationPreconditions(a, b VerifiedEvidenceEnvelope) error {
	if a.SigningDigest == b.SigningDigest {
		return fmt.Errorf("%w: both envelopes have the same bus_signing_digest, so this is a retry and not an equivocation", ErrEvidence)
	}
	// The sender is compared as its 20 address-codec bytes, not as text. That is
	// what the signing preimage, the content digest and evidence_id/fault_id all
	// frame. This low-level identity comparison remains codec-byte based even
	// though VerifyEvidenceEnvelope rejects a foreign HRP before key lookup.
	senderA, err := OperatorAddressCodecBytes(a.Fields.SenderOperatorAddress)
	if err != nil {
		return fmt.Errorf("%w: sender_operator_address of the first envelope: %v", ErrEvidence, err)
	}
	senderB, err := OperatorAddressCodecBytes(b.Fields.SenderOperatorAddress)
	if err != nil {
		return fmt.Errorf("%w: sender_operator_address of the second envelope: %v", ErrEvidence, err)
	}
	for _, check := range []struct {
		name  string
		equal bool
	}{
		{"chain_id", a.Fields.ChainID == b.Fields.ChainID},
		{"subject", a.Fields.Subject == b.Fields.Subject},
		{"kind", a.Fields.Kind == b.Fields.Kind},
		{"payload_type", a.Fields.PayloadType == b.Fields.PayloadType},
		{"sender_participant_type", a.Fields.SenderParticipantType == b.Fields.SenderParticipantType},
		{"sender_operator_address", bytes.Equal(senderA, senderB)},
		{"service_authorization_nonce", a.Fields.ServiceAuthorizationNonce == b.Fields.ServiceAuthorizationNonce},
		{"message_id", a.Fields.MessageID == b.Fields.MessageID},
		{"expires_at_unix_ms", a.Fields.ExpiresAtUnixMS == b.Fields.ExpiresAtUnixMS},
		{"action scope task_id", bytes.Equal(a.Scope.TaskID, b.Scope.TaskID)},
		{"action scope subject", a.Scope.ExpectedSubject == b.Scope.ExpectedSubject},
		// §5.5 requires the same payload-derived action scope, which is the whole
		// scope and not just the parts the subject happens to be built from. Two
		// OPEN_VERIFY envelopes differing only in verify_round share a task_id and
		// therefore a subject, but they are two rounds, not one equivocation - and
		// attributing them as one would write a BuilderFault for honest behaviour.
		{"action scope task_hash", bytes.Equal(a.Scope.TaskHash, b.Scope.TaskHash)},
		{"action scope model_id", equalOptionalString(a.Scope.ModelID, b.Scope.ModelID)},
		{"action scope verify_round", equalOptionalUint32(a.Scope.VerifyRound, b.Scope.VerifyRound)},
		{"action scope payload_actor", equalOptionalString(a.Scope.PayloadActor, b.Scope.PayloadActor)},
		// ORDER_BROADCAST carries its order out of band, and its task_hash is
		// derived from these bytes by the caller, so two orders that differ here
		// are two orders however similar their derived task_id looks.
		{"signed order bytes", bytes.Equal(a.OrderBytes, b.OrderBytes)},
	} {
		if !check.equal {
			return fmt.Errorf("%w: the two envelopes differ in %s, so they are not one equivocation",
				ErrEvidence, check.name)
		}
	}
	return nil
}

// equalOptionalString treats absent and present-but-empty as different, because
// the scope uses absence to mean "load this from Task authority" and an empty
// string would be a value.
func equalOptionalString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalOptionalUint32(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
