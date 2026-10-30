package dispatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func TestDispatchProofSelectsSignedCurrentOrPreviousNonce(t *testing.T) {
	rawCases, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "shared", "service_key_rotation_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Proofs []struct {
			Height  uint64 `json:"earliest_submit_height"`
			Retired uint64 `json:"previous_retired_height"`
			Allowed bool   `json:"allowed"`
		} `json:"proof_cases"`
	}
	if err = json.Unmarshal(rawCases, &cases); err != nil || len(cases.Proofs) != 3 {
		t.Fatal("missing published proof boundaries", err)
	}
	for _, name := range []string{"task.v1.SignedHandraiseRootV1", "task.v1.DispatchTicketV1", "task.v1.DispatchRecordV1", "task.v1.DispatchAcceptV1", "task.v1.DispatchRejectV1"} {
		t.Run(name, func(t *testing.T) {
			var row publishedVector
			for _, candidate := range published(t) {
				if candidate.MessageName == name {
					row = candidate
					break
				}
			}
			if row.Protobuf == "" {
				t.Fatal("missing signed vector")
			}
			role := ProofParticipantBuilder
			if name == "task.v1.DispatchAcceptV1" || name == "task.v1.DispatchRejectV1" {
				role = ProofParticipantCortex
			}
			key := ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
			opts := ProofKeyOptions{LookupProofKey: func(signer ServiceProofSigner) (ProofKeyBinding, error) {
				if signer != (ServiceProofSigner{role, vectorOperator, 1}) {
					t.Fatal("unsigned or wrong nonce", signer)
				}
				return key, nil
			}}
			raw := hexBytes(t, row.Protobuf)
			if err := VerifyDispatchProof("trueopen-phase1-vector-1", name, raw, opts); err != nil {
				t.Fatal(err)
			}
			fields, err := decode(name, raw, 0)
			if err != nil {
				t.Fatal(err)
			}
			nonceField := map[string]uint32{"task.v1.SignedHandraiseRootV1": 9, "task.v1.DispatchTicketV1": 27, "task.v1.DispatchRecordV1": 22, "task.v1.DispatchAcceptV1": 7, "task.v1.DispatchRejectV1": 7}[name]
			delete(fields, nonceField)
			if err := VerifyDispatchProof("trueopen-phase1-vector-1", name, encodeTestMessage(name, fields), opts); !errors.Is(err, ErrProofKeyUnavailable) {
				t.Fatal("missing signed nonce resolved a current key", err)
			}
			key.Status = ProofKeyPrevious
			key.PreviousRetiredHeight = 120
			if err := VerifyDispatchProof("trueopen-phase1-vector-1", name, raw, opts); !errors.Is(err, ErrProofKeyUnavailable) {
				t.Fatal("previous proof lacked order authority", err)
			}
			for _, proof := range cases.Proofs {
				key.PreviousRetiredHeight = proof.Retired
				opts.OrderEarliestSubmitHeight = &proof.Height
				err := VerifyDispatchProof("trueopen-phase1-vector-1", name, raw, opts)
				if (err == nil) != proof.Allowed {
					t.Fatal("retirement boundary", proof.Height, err)
				}
			}
			key.ServiceAuthorizationNonce = 2
			if err := VerifyDispatchProof("trueopen-phase1-vector-1", name, raw, opts); !errors.Is(err, ErrProofKeyUnavailable) {
				t.Fatal("unknown generation admitted", err)
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

func TestUnactivatedBuilderNonceCannotAuthorizeOfflineMessages(t *testing.T) {
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
		t.Fatal("typed Builder message omitted its signed nonce")
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
