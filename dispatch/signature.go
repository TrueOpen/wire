package dispatch

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// SignatureSize is the canonical compact R||S length.
const SignatureSize = 64

// VerifyDigestSignature verifies the original direct-digest low-S service signature.
func VerifyDigestSignature(pubKeyCompressed, digest, signature []byte) error {
	if len(digest) != sha256.Size {
		return fmt.Errorf("digest must be %d bytes", sha256.Size)
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("signature must be %d-byte compact R||S, got %d", SignatureSize, len(signature))
	}
	if len(pubKeyCompressed) != 33 || pubKeyCompressed[0] != 2 && pubKeyCompressed[0] != 3 {
		return errors.New("service key must be compressed secp256k1")
	}
	pubKey, err := secp256k1.ParsePubKey(pubKeyCompressed)
	if err != nil {
		return fmt.Errorf("parse service key: %w", err)
	}
	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(signature[:32]); overflow || r.IsZero() {
		return errors.New("signature R is zero or overflows")
	}
	if overflow := s.SetByteSlice(signature[32:]); overflow || s.IsZero() {
		return errors.New("signature S is zero or overflows")
	}
	if s.IsOverHalfOrder() {
		return errors.New("signature S is not low-S")
	}
	if !ecdsa.NewSignature(&r, &s).Verify(digest, pubKey) {
		return errors.New("signature does not verify")
	}
	return nil
}

// SignDigest signs a 32-byte digest directly with a secp256k1 private key and
// returns the 64-byte compact low-S R||S form. Exposed for senders and for
// vector generation; production senders normally wrap their keystore instead.
func SignDigest(privKey *secp256k1.PrivateKey, digest [32]byte) []byte {
	signature := ecdsa.Sign(privKey, digest[:]) // RFC 6979 deterministic, low-S normalized
	r := signature.R()
	s := signature.S()
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	out := make([]byte, SignatureSize)
	copy(out[:32], rBytes[:])
	copy(out[32:], sBytes[:])
	return out
}
