package dispatch

import (
	"bytes"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const vectorOperator = "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz"

func TestRejectProofSurvivesPendingRotationAndEmergencyRevoke(t *testing.T) {
	var row publishedVector
	for _, candidate := range published(t) {
		if candidate.MessageName == "task.v1.DispatchRejectV1" {
			row = candidate
			break
		}
	}
	if row.Protobuf == "" {
		t.Fatal("missing real signed reject vector")
	}
	signer := ServiceProofSigner{ProofParticipantCortex, vectorOperator, 1}
	current := ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
	opts := ProofKeyOptions{LookupProofKey: func(got ServiceProofSigner) (ProofKeyBinding, error) {
		if got != signer {
			return ProofKeyBinding{}, errors.New("unknown current binding")
		}
		return current, nil
	}}
	for _, status := range []ProofKeyStatus{ProofKeyActive, ProofKeyRevoked} {
		current.Status = status
		if err := VerifyDispatchProof("trueopen-phase1-vector-1", row.MessageName, hexBytes(t, row.Protobuf), opts); err != nil {
			t.Fatal("waiting or revoke invalidated an honest reject proof", status, err)
		}
	}
	current = ProofKeyBinding{PublicKey: secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32)).PubKey().SerializeCompressed(), ServiceAuthorizationNonce: 2, Status: ProofKeyActive}
	if err := VerifyDispatchProof("trueopen-phase1-vector-1", row.MessageName, hexBytes(t, row.Protobuf), opts); !errors.Is(err, ErrProofKeyUnavailable) {
		t.Fatal("activated replacement resolved a retired generation", err)
	}
}

func TestBuilderDispatchProofDoesNotRequireAnAddedNonce(t *testing.T) {
	for _, name := range []string{"task.v1.SignedHandraiseRootV1", "task.v1.DispatchTicketV1", "task.v1.DispatchRecordV1"} {
		t.Run(name, func(t *testing.T) {
			var row publishedVector
			for _, candidate := range published(t) {
				if candidate.MessageName == name {
					row = candidate
					break
				}
			}
			if row.Protobuf == "" {
				t.Fatal("missing signed Builder vector")
			}
			current := ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
			opts := ProofKeyOptions{LookupProofKey: func(signer ServiceProofSigner) (ProofKeyBinding, error) {
				if signer != (ServiceProofSigner{ProofParticipantBuilder, vectorOperator, 0}) {
					t.Fatal("unsigned nonce copy entered the proof selector", signer)
				}
				return current, nil
			}}
			if err := VerifyDispatchProof("trueopen-phase1-vector-1", name, hexBytes(t, row.Protobuf), opts); err != nil {
				t.Fatal(err)
			}
			current.PublicKey = secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32)).PubKey().SerializeCompressed()
			current.ServiceAuthorizationNonce = 2
			if VerifyDispatchProof("trueopen-phase1-vector-1", name, hexBytes(t, row.Protobuf), opts) == nil {
				t.Fatal("retired Builder signature verified with the new current key")
			}
		})
	}
}

func TestProofLookupRejectsInvalidAuthority(t *testing.T) {
	valid := ServiceProofSigner{ProofParticipantCortex, account(t, 1), 1}
	for _, signer := range []ServiceProofSigner{{0, valid.OperatorAddress, 1}, {3, valid.OperatorAddress, 1}, {ProofParticipantCortex, valid.OperatorAddress, 0}, {ProofParticipantCortex, "invalid", 1}} {
		if _, err := resolveProofKey(signer, ProofKeyOptions{}); err == nil {
			t.Fatal("invalid selector admitted", signer)
		}
	}
	for _, binding := range []ProofKeyBinding{{ServiceAuthorizationNonce: 0, Status: ProofKeyActive}, {ServiceAuthorizationNonce: 2, Status: ProofKeyActive}, {ServiceAuthorizationNonce: 1, Status: ProofKeyStatus(3)}} {
		if _, err := resolveProofKey(valid, ProofKeyOptions{LookupProofKey: func(ServiceProofSigner) (ProofKeyBinding, error) { return binding, nil }}); !errors.Is(err, ErrProofKeyUnavailable) {
			t.Fatal("non-current authority admitted", binding, err)
		}
	}
}

func TestPendingBuilderNonceCannotAuthorizeOfflineMessagesEarly(t *testing.T) {
	var row publishedVector
	for _, candidate := range published(t) {
		if candidate.MessageName == "nexus.v1.OpenVerifyV1" {
			row = candidate
			break
		}
	}
	if row.Protobuf == "" {
		t.Fatal("missing signed Builder message")
	}
	raw := hexBytes(t, row.Protobuf)
	d, err := decode(row.MessageName, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	binding := bytesAt(d, 10)
	if !bytes.HasSuffix(binding, []byte{24, 1}) {
		t.Fatal("fixture binding changed")
	}
	withoutNonce := bytes.Replace(raw, wireBytes(10, binding), wireBytes(10, binding[:len(binding)-2]), 1)
	if _, err := DecodeSignedMessageV1(1, withoutNonce); err == nil {
		t.Fatal("typed Builder message used the unsigned dispatch nonce selector")
	}
	nextBinding := bytes.Clone(binding)
	nextBinding[len(nextBinding)-1] = 2
	nextMessage := bytes.Replace(raw, wireBytes(10, binding), wireBytes(10, nextBinding), 1)
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))
	digest, err := SigningDigest(row.MessageName, nextMessage)
	if err != nil {
		t.Fatal(err)
	}
	nextMessage = bytes.Replace(nextMessage, wireBytes(9, hexBytes(t, row.Signature)), wireBytes(9, SignDigest(key, digest)), 1)
	branch := append([]byte{8, 1}, wireBytes(2, nextMessage)...)
	branch = append(branch, 24, 1)
	proof := append([]byte{8, 2}, wireBytes(3, branch)...)
	current := ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
	opts := EvidenceVerifyOptions{ChainID: "trueopen-phase1-vector-1", LookupProofKey: func(ServiceProofSigner) (ProofKeyBinding, error) { return current, nil }}
	if _, err := VerifyBuilderEvidenceV2(proof, opts); err == nil {
		t.Fatal("pending key gained proof authority before activation")
	}
	current = ProofKeyBinding{PublicKey: key.PubKey().SerializeCompressed(), ServiceAuthorizationNonce: 2, Status: ProofKeyActive}
	if _, err := VerifyBuilderEvidenceV2(proof, opts); err != nil {
		t.Fatal("activated next binding cannot verify its own message", err)
	}
}
