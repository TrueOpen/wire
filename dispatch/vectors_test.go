package dispatch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type publishedVector struct {
	Name        string `json:"name"`
	MessageName string `json:"message_name"`
	Protobuf    string `json:"protobuf_hex"`
	Preimage    string `json:"preimage_hex"`
	Digest      string `json:"digest_hex"`
	Signature   string `json:"signature_hex"`
	PublicKey   string `json:"public_key_hex"`
}

func published(t *testing.T) []publishedVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []publishedVector `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Vectors
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPublishedSigningProjections(t *testing.T) {
	covered := map[string]bool{}
	for _, row := range published(t) {
		if row.MessageName == "" {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			raw := hexBytes(t, row.Protobuf)
			preimage, err := SigningPreimage(row.MessageName, raw)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(preimage) != row.Preimage {
				t.Fatal("Go projection differs from the independently encoded fields")
			}
			digest, err := SigningDigest(row.MessageName, raw)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest[:]) != row.Digest {
				t.Fatal("published digest mismatch")
			}
			if row.Signature != "" {
				if err = VerifyDigestSignature(hexBytes(t, row.PublicKey), digest[:], hexBytes(t, row.Signature)); err != nil {
					t.Fatal(err)
				}
			}
			unknown := append(append([]byte(nil), raw...), 0xf8, 0x3e, 1)
			if _, err = SigningDigest(row.MessageName, unknown); err == nil {
				t.Fatal("unknown field survived signing projection")
			}
			covered[row.MessageName] = true
		})
	}
	if len(covered) != len(signingDomains) {
		t.Fatal("a signed message has no published vector")
	}
}

func TestPublishedFullPoolOrder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Order struct {
			ChainID    string           `json:"chain_id"`
			TaskID     string           `json:"task_id"`
			PoolHash   string           `json:"pool_hash"`
			Height     uint64           `json:"reference_height"`
			Randomness string           `json:"randomness"`
			Members    []WeightedMember `json:"members"`
			Attempts   uint32           `json:"max_attempts"`
			Order      []uint32         `json:"order"`
		} `json:"weighted_order"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var random [32]byte
	copy(random[:], hexBytes(t, doc.Order.Randomness))
	order, err := DrawOrder(doc.Order.ChainID, random, doc.Order.Members, doc.Order.Attempts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, doc.Order.Order) {
		t.Fatal("draw differs from the independent SHA-256/rejection-sampling vector")
	}
}

func TestTypedEvidenceUsesCurrentProofBindingWithoutLiveState(t *testing.T) {
	var row publishedVector
	for _, v := range published(t) {
		if v.MessageName == "nexus.v1.OpenVerifyV1" && row.MessageName == "" {
			row = v
		}
	}
	a := hexBytes(t, row.Protobuf)
	output := bytes.Repeat([]byte{0x92}, 32)
	d, err := decode(row.MessageName, a, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := bytes.Replace(a, d[6][0].bytes, output, 1)
	digest, err := SigningDigest(row.MessageName, b)
	if err != nil {
		t.Fatal(err)
	}
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	b = bytes.Replace(b, hexBytes(t, row.Signature), SignDigest(key, digest), 1)
	branch := []byte{8, 1}
	branch = append(branch, wireBytes(2, a)...)
	branch = append(branch, wireBytes(3, b)...)
	proof := append([]byte{8, 2}, wireBytes(2, branch)...)
	opts := EvidenceVerifyOptions{ChainID: "trueopen-phase1-vector-1", LookupProofKey: func(signer ServiceProofSigner) (ProofKeyBinding, error) {
		return ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyRevoked}, nil
	}}
	verified, err := VerifyBuilderEvidenceV2(proof, opts)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Kind != EvidenceKindProposalEquivocation || verified.MessageA.Scope.TaskID != verified.MessageB.Scope.TaskID {
		t.Fatal("wrong proof scope")
	}
	otherSignature := alternateProof(key, verified.MessageA.SigningDigest)
	if bytes.Equal(otherSignature, hexBytes(t, row.Signature)) {
		t.Fatal("alternate proof must be distinct")
	}
	otherA := bytes.Replace(a, hexBytes(t, row.Signature), otherSignature, 1)
	otherBranch := append([]byte{8, 1}, wireBytes(2, otherA)...)
	otherBranch = append(otherBranch, wireBytes(3, b)...)
	other, err := VerifyBuilderEvidenceV2(append([]byte{8, 2}, wireBytes(2, otherBranch)...), opts)
	if err != nil || other.ContentDigest != verified.ContentDigest {
		t.Fatal("valid alternate signature changed objective identity", err)
	}
	swapped := []byte{8, 1}
	swapped = append(swapped, wireBytes(2, b)...)
	swapped = append(swapped, wireBytes(3, a)...)
	reverse, err := VerifyBuilderEvidenceV2(append([]byte{8, 2}, wireBytes(2, swapped)...), opts)
	if err != nil || reverse.ContentDigest != verified.ContentDigest {
		t.Fatal("pair ordering changes evidence identity", err)
	}
	wrongChain := opts
	wrongChain.ChainID = "another-chain"
	if _, err = VerifyBuilderEvidenceV2(proof, wrongChain); err == nil {
		t.Fatal("cross-chain proof accepted")
	}
	rotated := opts
	rotated.LookupProofKey = func(ServiceProofSigner) (ProofKeyBinding, error) {
		return ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 2, Status: ProofKeyActive}, nil
	}
	if _, err = VerifyBuilderEvidenceV2(proof, rotated); err == nil {
		t.Fatal("rotated historical proof binding accepted")
	}
	revoked := opts
	revoked.LookupProofKey = func(ServiceProofSigner) (ProofKeyBinding, error) {
		return ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyRevoked}, nil
	}
	if _, err = VerifyBuilderEvidenceV2(proof, revoked); err != nil {
		t.Fatal("revoked current Builder proof identity was lost", err)
	}
}
