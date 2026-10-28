package dispatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestRejectProofSurvivesRotationWithinFrozenWindow(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	current := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))
	var row publishedVector
	for _, v := range published(t) {
		if v.MessageName == "task.v1.DispatchRejectV1" {
			row = v
			break
		}
	}
	digest, err := SigningDigest(row.MessageName, hexBytes(t, row.Protobuf))
	if err != nil {
		t.Fatal(err)
	}
	signer := ServiceProofSigner{ProofParticipantCortex, "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz", 1}
	end, err := ProofKeyExpiryHeight(100, ProofRetentionWindows{2, 4, 64, 8, 32, 8})
	if err != nil || end != 178 {
		t.Fatal("unsafe retention horizon", end, err)
	}
	opts := ProofKeyOptions{Height: 178, LookupProofKey: func(got ServiceProofSigner) (ProofKeyBinding, error) {
		if got != signer {
			return ProofKeyBinding{}, errors.New("unknown generation")
		}
		return ProofKeyBinding{PublicKey: key.PubKey().SerializeCompressed(), ServiceAuthorizationNonce: 1, Status: ProofKeyRetained, RetiredHeight: 100, ProofExpiryHeight: end}, nil
	}}
	if err = VerifyDispatchProof("trueopen-phase1-vector-1", row.MessageName, hexBytes(t, row.Protobuf), opts); err != nil {
		t.Fatal("honest Builder lost its reject proof after Worker rotation", err)
	}
	if VerifyDigestSignature(current.PubKey().SerializeCompressed(), digest[:], hexBytes(t, row.Signature)) == nil {
		t.Fatal("test does not reproduce the current-key failure")
	}
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "shared", "service_key_proof_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Height   uint64 `json:"height"`
			Accepted bool   `json:"proof_accepted"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range fixture.Cases {
		check := opts
		check.Height = scenario.Height
		err = VerifyServiceProofSignature(signer, digest, hexBytes(t, row.Signature), check)
		if (err == nil) != scenario.Accepted || !scenario.Accepted && !errors.Is(err, ErrProofKeyUnavailable) {
			t.Fatal("published proof window mismatch", scenario.Height, err)
		}
	}
	for _, changed := range []ServiceProofSigner{{ProofParticipantBuilder, signer.OperatorAddress, 1}, {ProofParticipantCortex, signer.OperatorAddress, 2}, {ProofParticipantCortex, signer.OperatorAddress, 0}, {3, signer.OperatorAddress, 1}} {
		if VerifyServiceProofSignature(changed, digest, hexBytes(t, row.Signature), opts) == nil {
			t.Fatal("proof crossed role/generation")
		}
	}
	if err = VerifyServiceProofSignature(signer, digest, hexBytes(t, row.Signature), ProofKeyOptions{}); !errors.Is(err, ErrProofKeyUnavailable) {
		t.Fatal("missing key authority was not distinguished", err)
	}
}

func TestBuilderProofsRetainSignedAuthorizationNonce(t *testing.T) {
	for _, row := range published(t) {
		if row.MessageName != "task.v1.DispatchTicketV1" && row.MessageName != "task.v1.DispatchRecordV1" && row.MessageName != "task.v1.SignedHandraiseRootV1" && row.MessageName != "task.v1.DispatchAcceptV1" {
			continue
		}
		t.Run(row.MessageName, func(t *testing.T) {
			raw := hexBytes(t, row.Protobuf)
			digest, err := SigningDigest(row.MessageName, raw)
			if err != nil {
				t.Fatal(err)
			}
			role := ProofParticipantBuilder
			if row.MessageName == "task.v1.DispatchAcceptV1" {
				role = ProofParticipantCortex
			}
			signer := ServiceProofSigner{role, "trueopen1rfjz7r3u8t65teavh5utquj3kwvsj983p3jclz", 1}
			opts := ProofKeyOptions{Height: 120, LookupProofKey: func(got ServiceProofSigner) (ProofKeyBinding, error) {
				if got != signer {
					return ProofKeyBinding{}, errors.New("unexpected nonce")
				}
				return ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyRetained, RetiredHeight: 100, ProofExpiryHeight: 178}, nil
			}}
			if err = VerifyDispatchProof("trueopen-phase1-vector-1", row.MessageName, raw, opts); err != nil {
				t.Fatal(err)
			}
			// Builder projections put the new generation field last.
			if role == ProofParticipantCortex {
				return
			}
			changed := append([]byte(nil), raw...)
			changed[len(changed)-1] = 2
			other, err := SigningDigest(row.MessageName, changed)
			if err != nil || other == digest || VerifyDigestSignature(hexBytes(t, row.PublicKey), other[:], hexBytes(t, row.Signature)) == nil {
				t.Fatal("nonce was not signed", err)
			}
		})
	}
}

func TestProofRetentionUsesLongestWindowAndCheckedArithmetic(t *testing.T) {
	windows := ProofRetentionWindows{2, 4, 1, 1, 64, 8}
	if end, err := ProofKeyExpiryHeight(100, windows); err != nil || end != 178 {
		t.Fatal(end, err)
	}
	windows.OrderFreshnessMarginBlocks = 0
	if end, err := ProofKeyExpiryHeight(100, windows); err != nil || end != 177 {
		t.Fatal("future-order block was omitted", end, err)
	}
	for _, w := range []ProofRetentionWindows{{2, 4, math.MaxUint64, 1, 1, 1}, {2, 4, 1, 1, math.MaxUint64, 1}, {2, 4, 1, 1, 1, 1}} {
		if _, err := ProofKeyExpiryHeight(math.MaxUint64-1, w); err == nil {
			t.Fatal("overflow admitted")
		}
	}
	if _, err := ProofKeyExpiryHeight(0, windows); err == nil {
		t.Fatal("missing retirement height admitted")
	}
}
