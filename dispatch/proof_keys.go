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
	scope := d
	if ticketField != 0 {
		if len(d[ticketField]) != 1 {
			return fmt.Errorf("%w: missing winner ticket", ErrDecode)
		}
		if scope, err = decode("task.v1.DispatchTicketV1", d[ticketField][0].bytes, 1); err != nil {
			return err
		}
		operatorField = 7
	}
	chainField := uint32(2)
	if name == "task.v1.SignedHandraiseRootV1" {
		chainField = 1
	}
	if chainID == "" || string(bytesAt(scope, chainField)) != chainID {
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
	return verifySignedGeneration(ServiceProofSigner{role, operator, scalarAt(d, nonceField)}, digest, bytesAt(d, signatureField), opts)
}

// VerifyTicketBoundDispatchProof verifies a retained Builder stream message
// that names its attempt only by dispatch_ticket_hash: DispatchInputResponseV1,
// DispatchRevokeV1 or RecordResultNoticeV1. ticket is the raw
// task.v1.DispatchTicketV1 the caller already verified with VerifyDispatchProof;
// its signing digest must equal dispatch_ticket_hash, and its chain and
// builder_address fix the expected chain and signer. The message's own signed
// nonce selects current or previous exactly as VerifyDispatchProof does, with
// OrderEarliestSubmitHeight taken from that ticket's order. Retained messages
// keep their original signed bytes across reconnect and cutover.
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
	t, err := decode("task.v1.DispatchTicketV1", ticket, 0)
	if err != nil {
		return err
	}
	if chainID == "" || string(bytesAt(t, 2)) != chainID {
		return fmt.Errorf("%w: proof chain mismatch", ErrEvidence)
	}
	ticketHash, err := SigningDigest("task.v1.DispatchTicketV1", ticket)
	if err != nil {
		return err
	}
	if !bytes.Equal(ticketHash[:], bytesAt(d, hashField)) {
		return fmt.Errorf("%w: message names another dispatch ticket", ErrEvidence)
	}
	digest, err := SigningDigest(name, raw)
	if err != nil {
		return err
	}
	return verifySignedGeneration(ServiceProofSigner{ProofParticipantBuilder, string(bytesAt(t, 7)), scalarAt(d, nonceField)}, digest, bytesAt(d, signatureField), opts)
}

// verifySignedGeneration is the one current/previous selection rule for every
// nonce-bearing dispatch proof: positive signed nonce, current or the sole
// previous generation, and previous only for an order strictly before its
// retirement height.
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
