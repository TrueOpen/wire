package dispatch

import (
	"bytes"
	"errors"
	"fmt"
)

// Service proof selectors use the service identity domains, never VRF identities.
const (
	ProofParticipantCortex  int32 = 1
	ProofParticipantBuilder int32 = 2
)

// ErrProofKeyUnavailable distinguishes absent/expired authority from a bad
// signature. Missing required chain facts must not be converted into guilt.
var ErrProofKeyUnavailable = errors.New("dispatch: proof key unavailable")

// ServiceProofSigner selects a signed generation. Zero nonce is used only by
// nonce-free current Builder transport; every signed dispatch nonce is positive.
type ServiceProofSigner struct {
	ParticipantType           int32
	OperatorAddress           string
	ServiceAuthorizationNonce uint64
}

// ProofKeyStatus describes proof eligibility, not live transaction permissions.
type ProofKeyStatus uint8

const (
	ProofKeyActive ProofKeyStatus = iota + 1
	ProofKeyRevoked
	ProofKeyPrevious
)

// ProofKeyBinding is resolved by role/operator/nonce from authoritative state.
// Only current and one previous generation are resolvable. Previous is proof-only.
type ProofKeyBinding struct {
	PublicKey                 []byte
	ServiceAuthorizationNonce uint64
	Status                    ProofKeyStatus
	PreviousRetiredHeight     uint64
}

// ProofKeyOptions supplies current/previous resolution from authoritative state.
// Resolution alone grants no live permission. A transport consumer such as
// VerifyBuilderSyncRequest additionally requires current ACTIVE authority.
type ProofKeyOptions struct {
	LookupProofKey func(ServiceProofSigner) (ProofKeyBinding, error)
	// Required for previous-generation dispatch proofs; read from the signed
	// order or immutable accepted record, never a later live Session anchor.
	OrderEarliestSubmitHeight *uint64
}

func resolveProofKey(signer ServiceProofSigner, opts ProofKeyOptions) (ProofKeyBinding, error) {
	var empty ProofKeyBinding
	if signer.ParticipantType != ProofParticipantCortex && signer.ParticipantType != ProofParticipantBuilder || (signer.ServiceAuthorizationNonce == 0 && signer.ParticipantType != ProofParticipantBuilder) {
		return empty, fmt.Errorf("%w: invalid role or nonce", ErrProofKeyUnavailable)
	}
	if _, err := AddressBytes(signer.OperatorAddress); err != nil {
		return empty, err
	}
	if opts.LookupProofKey == nil {
		return empty, ErrProofKeyUnavailable
	}
	key, err := opts.LookupProofKey(signer)
	if err != nil {
		return empty, fmt.Errorf("%w: %w", ErrProofKeyUnavailable, err)
	}
	if key.ServiceAuthorizationNonce == 0 || signer.ServiceAuthorizationNonce != 0 && key.ServiceAuthorizationNonce != signer.ServiceAuthorizationNonce {
		return empty, fmt.Errorf("%w: generation mismatch", ErrProofKeyUnavailable)
	}
	switch key.Status {
	case ProofKeyActive, ProofKeyRevoked:
		if key.PreviousRetiredHeight != 0 {
			return empty, fmt.Errorf("%w: current key has a previous retirement height", ErrProofKeyUnavailable)
		}
	case ProofKeyPrevious:
		if signer.ServiceAuthorizationNonce == 0 || key.PreviousRetiredHeight == 0 {
			return empty, fmt.Errorf("%w: previous key requires a signed nonce and retirement height", ErrProofKeyUnavailable)
		}
	default:
		return empty, fmt.Errorf("%w: ineligible binding", ErrProofKeyUnavailable)
	}
	return key, nil
}

// VerifyServiceProofSignature verifies a fact with its resolved proof key.
// Callers must separately validate the fact's scope and admission
// window; successful cryptography never authorizes a new live submission.
func VerifyServiceProofSignature(signer ServiceProofSigner, digest [32]byte, signature []byte, opts ProofKeyOptions) error {
	_, err := verifyServiceProofSignature(signer, digest, signature, opts)
	return err
}

func verifyServiceProofSignature(signer ServiceProofSigner, digest [32]byte, signature []byte, opts ProofKeyOptions) (ProofKeyBinding, error) {
	key, err := resolveProofKey(signer, opts)
	if err != nil {
		return ProofKeyBinding{}, err
	}
	if err = VerifyDigestSignature(key.PublicKey, digest[:], signature); err != nil {
		return ProofKeyBinding{}, err
	}
	return key, nil
}

// VerifyDispatchProof resolves the signer from the exact signed dispatch
// material. Previous keys require an order strictly before their retirement.
// Submitter authorization and live traffic separately require current authority.
// DispatchResultHeaderV1 is signed by its winner ticket's Builder and checked
// against that ticket's chain; relayed copies keep their original signed bytes.
// Its signed nonce may not precede the winner ticket's nonce. Verifying a header
// authenticates only its signer: the embedded winner ticket and accept are not
// verified here, and a consumer verifies both separately before trusting who won.
func VerifyDispatchProof(chainID, name string, raw []byte, opts ProofKeyOptions) error {
	role := ProofParticipantBuilder
	var operatorField, nonceField, signatureField uint32
	memberField, ticketField := uint32(0), uint32(0)
	switch name {
	case "task.v1.SignedHandraiseRootV1":
		operatorField, nonceField, signatureField = 2, 9, 7
	case "task.v1.DispatchTicketV1":
		operatorField, nonceField, signatureField = 7, 27, 25
	case "task.v1.DispatchRecordV1":
		operatorField, nonceField, signatureField = 7, 22, 20
	case "task.v1.DispatchAcceptV1":
		role, memberField, nonceField, signatureField = ProofParticipantCortex, 6, 7, 8
	case "task.v1.DispatchRejectV1":
		role, memberField, nonceField, signatureField = ProofParticipantCortex, 6, 7, 9
	case "task.v1.VerifierHandraiseV1":
		role, memberField, nonceField, signatureField = ProofParticipantCortex, 9, 11, 13
	case "nexus.v1.DispatchResultHeaderV1":
		ticketField, nonceField, signatureField = 2, 6, 5
	default:
		return fmt.Errorf("unsupported dispatch proof %s", name)
	}
	d, err := decode(name, raw, 0)
	if err != nil {
		return err
	}
	nonce := scalarAt(d, nonceField)
	scope, scopeName := d, name
	if ticketField != 0 {
		if len(d[ticketField]) != 1 {
			return fmt.Errorf("%w: missing winner ticket", ErrDecode)
		}
		scopeName = dispatchTicketMessage
		if scope, err = decode(scopeName, d[ticketField][0].bytes, 1); err != nil {
			return err
		}
		operatorField = fieldNumber(scopeName, "builder_address")
		if err = requireNotBeforeTicket(nonce, scope); err != nil {
			return err
		}
	}
	if chainID == "" || string(bytesAt(scope, fieldNumber(scopeName, "chain_id"))) != chainID {
		return fmt.Errorf("%w: proof chain mismatch", ErrEvidence)
	}
	operator := string(bytesAt(scope, operatorField))
	if memberField != 0 {
		if len(d[memberField]) != 1 {
			return fmt.Errorf("%w: missing proof signer", ErrDecode)
		}
		member, e := decode("task.v1.CandidateMemberRefV1", d[memberField][0].bytes, 1)
		if e != nil {
			return e
		}
		operator = string(bytesAt(member, 4))
	}
	digest, err := SigningDigest(name, raw)
	if err != nil {
		return err
	}
	return verifySignedGeneration(ServiceProofSigner{role, operator, nonce}, digest, bytesAt(d, signatureField), opts)
}

const dispatchTicketMessage = "task.v1.DispatchTicketV1"

// fieldNumber resolves a field by name from the pinned table, so a projection
// never reads another message's field number by accident.
func fieldNumber(message, field string) uint32 {
	for number, spec := range protoTables[message] {
		if spec.name == field {
			return number
		}
	}
	panic("dispatch: unknown field " + message + "." + field)
}

// requireNotBeforeTicket rejects a retained message whose signed generation is
// older than its ticket's. Rotation only advances the nonce and the Builder
// never signs these messages before the ticket, so an older generation can only
// be a retired key signing for a ticket issued under a newer one.
func requireNotBeforeTicket(nonce uint64, ticket decoded) error {
	ticketNonce := scalarAt(ticket, fieldNumber(dispatchTicketMessage, "service_authorization_nonce"))
	if ticketNonce == 0 || nonce < ticketNonce {
		return fmt.Errorf("%w: signed generation precedes its dispatch ticket", ErrProofKeyUnavailable)
	}
	return nil
}

// VerifyTicketBoundDispatchProof verifies a retained Builder stream message
// that names its attempt only by dispatch_ticket_hash: DispatchInputResponseV1,
// DispatchRevokeV1 or RecordResultNoticeV1. ticket is the raw
// task.v1.DispatchTicketV1 whose signing digest must equal dispatch_ticket_hash.
// That hash pins the ticket's chain_id, builder_address and nonce, which fix the
// expected chain, the signer and the oldest admissible generation; the ticket
// signature is outside its projection, so this function does not need a
// pre-verified ticket. The caller must guarantee that OrderEarliestSubmitHeight
// comes from the order this ticket belongs to. The message's own signed nonce,
// never older than the ticket's, selects current or previous exactly as
// VerifyDispatchProof does. Retained messages keep their original signed bytes
// across reconnect and cutover.
func VerifyTicketBoundDispatchProof(chainID, name string, raw, ticket []byte, opts ProofKeyOptions) error {
	var hashField, nonceField, signatureField uint32
	switch name {
	case "nexus.v1.DispatchInputResponseV1":
		hashField, nonceField, signatureField = 2, 9, 8
	case "nexus.v1.DispatchRevokeV1":
		hashField, nonceField, signatureField = 2, 6, 4
	case "nexus.v1.RecordResultNoticeV1":
		hashField, nonceField, signatureField = 1, 6, 5
	default:
		return fmt.Errorf("unsupported ticket-bound dispatch proof %s", name)
	}
	d, err := decode(name, raw, 0)
	if err != nil {
		return err
	}
	t, err := decode(dispatchTicketMessage, ticket, 0)
	if err != nil {
		return err
	}
	if chainID == "" || string(bytesAt(t, fieldNumber(dispatchTicketMessage, "chain_id"))) != chainID {
		return fmt.Errorf("%w: proof chain mismatch", ErrEvidence)
	}
	ticketHash, err := SigningDigest(dispatchTicketMessage, ticket)
	if err != nil {
		return err
	}
	if !bytes.Equal(ticketHash[:], bytesAt(d, hashField)) {
		return fmt.Errorf("%w: message names another dispatch ticket", ErrEvidence)
	}
	nonce := scalarAt(d, nonceField)
	if err = requireNotBeforeTicket(nonce, t); err != nil {
		return err
	}
	digest, err := SigningDigest(name, raw)
	if err != nil {
		return err
	}
	operator := string(bytesAt(t, fieldNumber(dispatchTicketMessage, "builder_address")))
	return verifySignedGeneration(ServiceProofSigner{ProofParticipantBuilder, operator, nonce}, digest, bytesAt(d, signatureField), opts)
}

// VerifyDispatchStreamBinding authenticates the live DispatchStreamBindingV1
// that opens a stream: this chain, the receiving Builder, and the Cortex
// signature by the current ACTIVE key named by its nonce. Revoked, previous and
// pending keys never authorize it. The binding is checked once per connection,
// so the receiving Builder must close an established stream when that key is no
// longer the Cortex's current ACTIVE key. The consumer additionally enforces
// one use per stream_nonce and the frame-level nonce echo.
func VerifyDispatchStreamBinding(chainID, builderOperator string, raw []byte, opts ProofKeyOptions) error {
	const name = "nexus.v1.DispatchStreamBindingV1"
	d, err := decode(name, raw, 0)
	if err != nil {
		return err
	}
	if chainID == "" || string(bytesAt(d, fieldNumber(name, "chain_id"))) != chainID || string(bytesAt(d, fieldNumber(name, "builder_operator"))) != builderOperator {
		return fmt.Errorf("%w: binding chain or Builder mismatch", ErrEvidence)
	}
	if _, err = AddressBytes(builderOperator); err != nil {
		return err
	}
	digest, err := SigningDigest(name, raw)
	if err != nil {
		return err
	}
	signer := ServiceProofSigner{ProofParticipantCortex, string(bytesAt(d, fieldNumber(name, "cortex_operator"))), scalarAt(d, fieldNumber(name, "service_authorization_nonce"))}
	key, err := verifyServiceProofSignature(signer, digest, bytesAt(d, fieldNumber(name, "service_signature")), opts)
	if err != nil {
		return err
	}
	if key.Status != ProofKeyActive {
		return fmt.Errorf("%w: stream binding requires current ACTIVE authority", ErrProofKeyUnavailable)
	}
	return nil
}

// verifySignedGeneration is the current/previous rule with the order bound for
// nonce-bearing dispatch proofs: positive signed nonce, current (ACTIVE or
// REVOKED, never bounded by order height) or the sole previous generation, and
// previous only for an order strictly before its retirement height. It is not
// the only proof rule: VerifyServiceProofSignature, and the OPEN_VERIFY and
// VERIFIER_ASSIGNMENT_NOTIFY evidence in VerifyBuilderEvidenceV2 built on it,
// resolve previous without this bound; that path's window comes from the Task
// responsibility nonce and the evidence admissibility window.
func verifySignedGeneration(signer ServiceProofSigner, digest [32]byte, signature []byte, opts ProofKeyOptions) error {
	if signer.ServiceAuthorizationNonce == 0 {
		return fmt.Errorf("%w: signed proof nonce must be positive", ErrProofKeyUnavailable)
	}
	key, err := resolveProofKey(signer, opts)
	if err != nil {
		return err
	}
	if key.Status == ProofKeyPrevious && (opts.OrderEarliestSubmitHeight == nil || *opts.OrderEarliestSubmitHeight >= key.PreviousRetiredHeight) {
		return fmt.Errorf("%w: previous key cannot prove a post-cutover order", ErrProofKeyUnavailable)
	}
	return VerifyDigestSignature(key.PublicKey, digest[:], signature)
}
