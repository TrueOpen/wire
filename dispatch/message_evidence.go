package dispatch

import (
	"bytes"
	"fmt"
)

// MaxBuilderEvidenceBytesV2 bounds an entire two-message proof container.
const MaxBuilderEvidenceBytesV2 = 2_100_000

// StreamActionScopeV1 is the explicit plain scope of one signed Builder action.
// It is not a generated protobuf, persistent state, or an authority decision.
type StreamActionScopeV1 struct {
	MessageKind  int32
	TaskID       [32]byte
	TaskHash     [32]byte
	ModelID      *[32]byte
	VerifyRound  uint32
	PayloadActor string
}

// SignedMessageV1 contains the canonical fields a Task authority check needs.
type SignedMessageV1 struct {
	Binding       BuilderMessageBindingV1
	Scope         StreamActionScopeV1
	SigningDigest [32]byte
	Signature     []byte
}

// BuilderMessageBindingV1 is the signed key-generation identity, projected
// from the common metadata of the business message itself.
type BuilderMessageBindingV1 struct {
	ChainID                   string
	BuilderAddress            string
	ServiceAuthorizationNonce uint64
}

func hashAt(d decoded, n uint32) ([32]byte, error) {
	var out [32]byte
	if len(d[n]) != 1 || len(d[n][0].bytes) != 32 {
		return out, fmt.Errorf("%w: expected raw32 field %d", ErrDecode, n)
	}
	copy(out[:], d[n][0].bytes)
	return out, nil
}

// DecodeSignedMessageV1 strictly resolves only the two Builder evidence kinds.
// The field paths below are the explicit scope table, not field-name inference.
func DecodeSignedMessageV1(kind int32, raw []byte) (SignedMessageV1, error) {
	var result SignedMessageV1
	name := ""
	signatureField := uint32(0)
	roundField := uint32(0)
	switch kind {
	case 1:
		name = "nexus.v1.OpenVerifyV1"
		signatureField = 9
		roundField = 8
	case 2:
		name = "nexus.v1.VerifierAssignmentNotifyV1"
		signatureField = 10
		roundField = 3
	default:
		return result, fmt.Errorf("%w: inactive stream evidence kind", ErrDecode)
	}
	d, err := decode(name, raw, 0)
	if err != nil {
		return result, err
	}
	result.Scope.MessageKind = kind
	result.Scope.TaskID, err = hashAt(d, 1)
	if err != nil {
		return result, err
	}
	result.Scope.TaskHash, err = hashAt(d, 2)
	if err != nil {
		return result, err
	}
	if len(d[roundField]) != 1 || d[roundField][0].varint == 0 {
		return result, fmt.Errorf("%w: missing verify round", ErrDecode)
	}
	result.Scope.VerifyRound = uint32(d[roundField][0].varint)
	bindingField := uint32(10)
	if kind == 2 {
		bindingField = 11
	}
	if len(d[bindingField]) != 1 {
		return result, fmt.Errorf("%w: missing signed Builder binding", ErrDecode)
	}
	binding, e := decode("nexus.v1.BuilderMessageBindingV1", d[bindingField][0].bytes, 1)
	if e != nil {
		return result, e
	}
	if len(binding[1]) != 1 || len(binding[1][0].bytes) == 0 || len(binding[2]) != 1 {
		return result, fmt.Errorf("%w: incomplete signed Builder identity", ErrDecode)
	}
	result.Binding.ChainID = string(binding[1][0].bytes)
	result.Binding.BuilderAddress = string(binding[2][0].bytes)
	if _, e := AddressBytes(result.Binding.BuilderAddress); e != nil {
		return result, e
	}
	if len(binding[3]) != 0 {
		result.Binding.ServiceAuthorizationNonce = binding[3][0].varint
	}
	if result.Binding.ServiceAuthorizationNonce == 0 {
		return result, fmt.Errorf("%w: signed Builder binding nonce must be positive", ErrDecode)
	}
	if kind == 1 {
		model, e := hashAt(d, 3)
		if e != nil {
			return result, e
		}
		result.Scope.ModelID = &model
		if len(d[7]) != 1 {
			return result, fmt.Errorf("%w: missing Worker actor", ErrDecode)
		}
		result.Scope.PayloadActor = string(d[7][0].bytes)
	}
	if len(d[signatureField]) != 1 || len(d[signatureField][0].bytes) != SignatureSize {
		return result, fmt.Errorf("%w: missing compact signature", ErrDecode)
	}
	result.Signature = append([]byte(nil), d[signatureField][0].bytes...)
	result.SigningDigest, err = SigningDigest(name, raw)
	return result, err
}

// VerifiedBuilderEvidenceV2 is a cryptographically checked proof. The caller
// must still enforce the Task authority, stage, admissibility and finality.
type VerifiedBuilderEvidenceV2 struct {
	Tag             uint32
	Kind            int32
	MessageA        *SignedMessageV1
	MessageB        *SignedMessageV1
	Violation       int32
	DataUnavailable *DataUnavailableContent
	ContentDigest   [32]byte
}

// EvidenceVerifyOptions supplies chain authority without generated imports.
type EvidenceVerifyOptions struct {
	ChainID        string
	LookupProofKey func(ServiceProofSigner) (ProofKeyBinding, error)
}

// VerifyBuilderEvidenceV2 is the sole generated-code-free evidence verifier.
// A revoked current key verifies old facts only; pending keys never authorize proofs.
func VerifyBuilderEvidenceV2(raw []byte, opts EvidenceVerifyOptions) (VerifiedBuilderEvidenceV2, error) {
	var result VerifiedBuilderEvidenceV2
	if opts.ChainID == "" {
		return result, fmt.Errorf("%w: missing local chain", ErrEvidence)
	}
	d, err := decode("task.v1.BuilderEvidenceV2", raw, 0)
	if err != nil {
		return result, err
	}
	if len(d[1]) != 1 || d[1][0].varint != 2 {
		return result, fmt.Errorf("%w: evidence schema version", ErrDecode)
	}
	for _, tag := range []uint32{2, 3, 5} {
		if len(d[tag]) != 0 {
			result.Tag = tag
		}
	}
	if result.Tag == 0 {
		return result, fmt.Errorf("%w: missing evidence branch", ErrDecode)
	}
	result.Kind, err = EvidenceKindForTag(result.Tag)
	if err != nil {
		return result, err
	}
	if result.Tag == 5 {
		ref, e := decode("task.v1.DataUnavailableStateReferenceV1", d[5][0].bytes, 1)
		if e != nil {
			return result, e
		}
		task, e := hashAt(ref, 1)
		if e != nil {
			return result, e
		}
		if len(ref[2]) != 1 || ref[2][0].varint != 1 || len(ref[3]) != 1 {
			return result, fmt.Errorf("%w: data unavailable scope", ErrDecode)
		}
		content := DataUnavailableContent{TaskID: task[:], VerifyRound: 1, BuilderOperator: string(ref[3][0].bytes)}
		result.ContentDigest, e = DataUnavailableDigest(content)
		result.DataUnavailable = &content
		return result, e
	}
	branchName := "task.v1.SignedMessageEquivocationV2"
	if result.Tag == 3 {
		branchName = "task.v1.SignedMessageProtocolFaultV2"
	}
	branch, e := decode(branchName, d[result.Tag][0].bytes, 1)
	if e != nil {
		return result, e
	}
	if len(branch[1]) != 1 || len(branch[2]) != 1 {
		return result, fmt.Errorf("%w: empty signed proof", ErrDecode)
	}
	a, e := DecodeSignedMessageV1(int32(branch[1][0].varint), branch[2][0].bytes)
	if e != nil {
		return result, e
	}
	if a.Binding.ChainID != opts.ChainID {
		return result, fmt.Errorf("%w: chain or key authority unavailable", ErrEvidence)
	}
	key, e := verifyServiceProofSignature(ServiceProofSigner{ParticipantType: ProofParticipantBuilder, OperatorAddress: a.Binding.BuilderAddress, ServiceAuthorizationNonce: a.Binding.ServiceAuthorizationNonce}, a.SigningDigest, a.Signature, ProofKeyOptions{LookupProofKey: opts.LookupProofKey})
	if e != nil {
		return result, e
	}
	result.MessageA = &a
	if result.Tag == 3 {
		if len(branch[3]) != 1 {
			return result, fmt.Errorf("%w: missing violation", ErrDecode)
		}
		result.Violation = int32(branch[3][0].varint)
		result.ContentDigest, e = InvalidStageDigest(InvalidStageContent{MessageKind: a.Scope.MessageKind, SigningDigest: a.SigningDigest[:], Violation: result.Violation})
		return result, e
	}
	if len(branch[3]) != 1 {
		return result, fmt.Errorf("%w: missing equivocation pair", ErrDecode)
	}
	b, e := DecodeSignedMessageV1(a.Scope.MessageKind, branch[3][0].bytes)
	if e != nil {
		return result, e
	}
	if e = VerifyDigestSignature(key.PublicKey, b.SigningDigest[:], b.Signature); e != nil {
		return result, e
	}
	if a.Binding != b.Binding || a.Scope.TaskID != b.Scope.TaskID || a.Scope.VerifyRound != b.Scope.VerifyRound || bytes.Equal(a.SigningDigest[:], b.SigningDigest[:]) {
		return result, fmt.Errorf("%w: messages are not conflicting actions in one scope", ErrEvidence)
	}
	result.MessageB = &b
	result.ContentDigest, e = EquivocationDigest(EquivocationContent{MessageKind: a.Scope.MessageKind, DigestA: a.SigningDigest[:], DigestB: b.SigningDigest[:]})
	return result, e
}
