package dispatch

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestCompactSignatureRejectsOtherProfiles(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	digest := sha256.Sum256([]byte("direct digest profile"))
	sig := SignDigest(key, digest)
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(sig[32:])
	high := scalar.Negate().Bytes()
	highS := append(append([]byte(nil), sig[:32]...), high[:]...)
	zeroR := append(make([]byte, 32), sig[32:]...)
	zeroS := append(append([]byte(nil), sig[:32]...), make([]byte, 32)...)
	for name, bad := range map[string][]byte{
		"high S": highS, "zero R": zeroR, "zero S": zeroS,
		"overflow": bytes.Repeat([]byte{255}, 64), "recoverable": append(sig, 27),
		"DER": ecdsa.Sign(key, digest[:]).Serialize(), "truncated": sig[:63],
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyDigestSignature(key.PubKey().SerializeCompressed(), digest[:], bad) == nil {
				t.Fatal("wrong signature profile accepted")
			}
		})
	}
	wrong := digest
	wrong[0] ^= 1
	if VerifyDigestSignature(key.PubKey().SerializeCompressed(), wrong[:], sig) == nil {
		t.Fatal("signature authorizes another digest")
	}
}

// A different fixed nonce produces another mathematically valid proof for the
// same message. This is test-only arithmetic, not an alternative signing API.
func alternateProof(key *secp256k1.PrivateKey, digest [32]byte) []byte {
	n := secp256k1.S256().Params().N
	k := big.NewInt(2)
	x, _ := secp256k1.S256().ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(x, n)
	s := new(big.Int).Mul(r, new(big.Int).SetBytes(key.Serialize()))
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, new(big.Int).ModInverse(k, n)).Mod(s, n)
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	out := make([]byte, SignatureSize)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}
