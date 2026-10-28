package dispatch

import (
	"errors"
	"fmt"
	"math"
)

// Service proof selectors use the service identity domains, never VRF identities.
const (
	ProofParticipantCortex  int32 = 1
	ProofParticipantBuilder int32 = 2
)

// ErrProofKeyUnavailable distinguishes absent/expired authority from a bad
// signature. Missing required chain facts must not be converted into guilt.
var ErrProofKeyUnavailable = errors.New("dispatch: proof key unavailable")

// ServiceProofSigner names exactly one registered key generation and role.
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
	ProofKeyRetained
)

// ProofKeyBinding is resolved by role/operator/nonce from authoritative state.
// Retained keys additionally require the frozen retirement and expiry heights.
type ProofKeyBinding struct {
	PublicKey                 []byte
	ServiceAuthorizationNonce uint64
	Status                    ProofKeyStatus
	RetiredHeight             uint64
	ProofExpiryHeight         uint64
}

// ProofKeyOptions supplies chain height and generation-specific key resolution.
// It must never be used to authorize live streams, orders or transactions.
type ProofKeyOptions struct {
	Height         uint64
	LookupProofKey func(ServiceProofSigner) (ProofKeyBinding, error)
}

func resolveProofKey(signer ServiceProofSigner, opts ProofKeyOptions) (ProofKeyBinding, error) {
	var empty ProofKeyBinding
	if signer.ParticipantType != ProofParticipantCortex && signer.ParticipantType != ProofParticipantBuilder || signer.ServiceAuthorizationNonce == 0 {
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
	if key.ServiceAuthorizationNonce != signer.ServiceAuthorizationNonce {
		return empty, fmt.Errorf("%w: generation mismatch", ErrProofKeyUnavailable)
	}
	switch key.Status {
	case ProofKeyActive, ProofKeyRevoked:
	case ProofKeyRetained:
		if key.RetiredHeight == 0 || key.ProofExpiryHeight < key.RetiredHeight || opts.Height < key.RetiredHeight || opts.Height > key.ProofExpiryHeight {
			return empty, fmt.Errorf("%w: retained generation outside proof window", ErrProofKeyUnavailable)
		}
	default:
		return empty, fmt.Errorf("%w: ineligible binding", ErrProofKeyUnavailable)
	}
	return key, nil
}

// VerifyServiceProofSignature verifies a generation-bound fact even after key
// rotation. Callers must separately validate the fact's scope and admission
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
// material, never from a caller-supplied role or nonce copy. It is proof-only;
// admission and live traffic still require the current ACTIVE binding.
func VerifyDispatchProof(chainID, name string, raw []byte, opts ProofKeyOptions) error {
	role := ProofParticipantBuilder
	var operatorField, nonceField, signatureField uint32
	memberField := uint32(0)
	switch name {
	case "task.v1.SignedHandraiseRootV1":
		operatorField, nonceField, signatureField = 2, 8, 7
	case "task.v1.DispatchTicketV1":
		operatorField, nonceField, signatureField = 7, 26, 25
	case "task.v1.DispatchRecordV1":
		operatorField, nonceField, signatureField = 7, 21, 20
	case "task.v1.DispatchAcceptV1":
		role, memberField, nonceField, signatureField = ProofParticipantCortex, 6, 7, 8
	case "task.v1.DispatchRejectV1":
		role, memberField, nonceField, signatureField = ProofParticipantCortex, 6, 7, 9
	default:
		return fmt.Errorf("unsupported dispatch proof %s", name)
	}
	d, err := decode(name, raw, 0)
	if err != nil {
		return err
	}
	chainField := uint32(2)
	if name == "task.v1.SignedHandraiseRootV1" {
		chainField = 1
	}
	if chainID == "" || string(bytesAt(d, chainField)) != chainID {
		return fmt.Errorf("%w: proof chain mismatch", ErrEvidence)
	}
	operator := string(bytesAt(d, operatorField))
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
	return VerifyServiceProofSignature(ServiceProofSigner{role, operator, scalarAt(d, nonceField)}, digest, bytesAt(d, signatureField), opts)
}

// ProofRetentionWindows reuses effective dispatch parameters at key retirement.
// No additional retention parameter or independent clock is introduced.
type ProofRetentionWindows struct {
	OrderFreshnessMarginBlocks            uint64
	RecordDeadlineBlocks                  uint64
	DispatchCompensationClaimWindowBlocks uint64
	DispatchCompensationRebuttalBlocks    uint64
	DispatchChallengeWindowBlocks         uint64
	DispatchChallengeResponseBlocks       uint64
}

// ProofKeyExpiryHeight returns the inclusive minimum safe proof retention end:
// retirement + max(1,freshness) + record deadline + max(claim+rebuttal, challenge+response).
// The one-block future-order tolerance remains even when backward freshness is zero.
// Governance must extend retained rows before extending admissibility windows.
func ProofKeyExpiryHeight(retiredHeight uint64, windows ProofRetentionWindows) (uint64, error) {
	add := func(a, b uint64) (uint64, error) {
		if a > math.MaxUint64-b {
			return 0, fmt.Errorf("proof retention height overflow")
		}
		return a + b, nil
	}
	claim, err := add(windows.DispatchCompensationClaimWindowBlocks, windows.DispatchCompensationRebuttalBlocks)
	if err != nil {
		return 0, err
	}
	challenge, err := add(windows.DispatchChallengeWindowBlocks, windows.DispatchChallengeResponseBlocks)
	if err != nil {
		return 0, err
	}
	if challenge > claim {
		claim = challenge
	}
	end := retiredHeight
	lead := windows.OrderFreshnessMarginBlocks
	if lead < 1 {
		lead = 1
	}
	for _, interval := range []uint64{lead, windows.RecordDeadlineBlocks, claim} {
		end, err = add(end, interval)
		if err != nil {
			return 0, err
		}
	}
	// The rebuildable prune index needs end+1 to be representable.
	if retiredHeight == 0 || windows.RecordDeadlineBlocks == 0 || end == math.MaxUint64 {
		return 0, fmt.Errorf("invalid proof retention bounds")
	}
	return end, nil
}
