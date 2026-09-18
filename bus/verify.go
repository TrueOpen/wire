package bus

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Verification failure classes, one per step of the frozen order, so every
// implementation reports the same class first for the same broken envelope
// and tests can assert "which step fails first".
var (
	// ErrStructure is step 1: size bound, schema and field-shape violations.
	ErrStructure = errors.New("BUS_ENVELOPE_STRUCTURE")
	// ErrRouting is step 2: subject, kind and payload_type routing violations.
	ErrRouting = errors.New("BUS_ENVELOPE_ROUTING")
	// ErrChainFresh is step 3: chain identity and freshness violations.
	ErrChainFresh = errors.New("BUS_ENVELOPE_CHAIN_FRESH")
	// ErrPayload is step 4: payload digest mismatches.
	ErrPayload = errors.New("BUS_ENVELOPE_PAYLOAD")
	// ErrKeyBinding is step 5: current service key lookup and binding violations.
	ErrKeyBinding = errors.New("BUS_ENVELOPE_KEY_BINDING")
	// ErrSignature is step 6: signature format and verification failures.
	ErrSignature = errors.New("BUS_ENVELOPE_SIGNATURE")
	// ErrReplay is step 7: replay-store conflicts.
	ErrReplay = errors.New("BUS_ENVELOPE_REPLAY")
	// ErrStoreFailure reports a replay-store infrastructure fault, never a
	// protocol violation by the sender.
	ErrStoreFailure = errors.New("BUS_ENVELOPE_STORE_FAILURE")
)

// KeyBinding is the current service key a receiver resolved for
// (participant_type, operator_address) at verification time. There is no
// historical-key fallback: rotation between send and receive rejects the
// envelope.
type KeyBinding struct {
	// PubKeyCompressed is the 33-byte compressed secp256k1 service key.
	PubKeyCompressed []byte
	// AuthorizationNonce must equal the envelope's field 7.
	AuthorizationNonce uint64
	// Active reports whether the binding status is ACTIVE.
	Active bool
}

// KeyLookup resolves the current on-chain service key binding. Envelopes never
// carry a public key; the declared operator address inside the signed
// projection selects which registered key must verify.
type KeyLookup func(participantType int32, operatorAddress string) (KeyBinding, error)

// VerifyOptions carries the receiver-local facts one Verify call needs.
type VerifyOptions struct {
	// ChainID is the local task chain identity.
	ChainID string
	// Subject is the actual transport subject the envelope arrived on; it
	// must equal the signed subject byte-for-byte.
	Subject string
	// NowUnixMS is the receiver clock.
	NowUnixMS uint64
	// RawSize is the received encoded envelope size in bytes. It is required and
	// checked against the fixed MaxEnvelopeBytes protocol constant.
	RawSize int
	// LookupKey resolves the current service key binding. Required.
	LookupKey KeyLookup
	// Replay records accepted envelopes. Optional; nil skips step 7 (for
	// pure-function verification in tests and tools).
	Replay ReplayStore
	// ReplaySafetyMarginMS extends the replay tombstone past expiry.
	ReplaySafetyMarginMS uint64
}

// Verify checks one received envelope in the frozen order:
//
//	1 size and structure -> 2 subject/kind/payload_type routing ->
//	3 chain identity and freshness -> 4 payload digest ->
//	5 current key binding -> 6 signature -> 7 replay store
//
// Cheap local checks precede the chain lookup and the signature operation, so
// garbage cannot spend receiver resources. Callers must not decode the payload
// before Verify returns nil. A non-nil error wraps exactly one class above.
func Verify(fields Fields, payload []byte, signature []byte, opts VerifyOptions) error {
	// 1 size and structure
	if opts.RawSize <= 0 || opts.RawSize > MaxEnvelopeBytes {
		return fmt.Errorf("%w: envelope size must be 1..%d bytes", ErrStructure, MaxEnvelopeBytes)
	}
	if len(payload) == 0 {
		return fmt.Errorf("%w: payload is required", ErrStructure)
	}
	if _, err := operatorAddressCodecBytesForHRP(fields.SenderOperatorAddress, OperatorAddressHRPV1); err != nil {
		return fmt.Errorf("%w: sender_operator_address: %v", ErrStructure, err)
	}
	if err := validateProjection(fields); err != nil {
		return fmt.Errorf("%w: %v", ErrStructure, err)
	}
	// 2 routing: actual subject, kind -> payload_type mapping
	if fields.Subject != opts.Subject {
		return fmt.Errorf("%w: subject does not match transport subject", ErrRouting)
	}
	if expected, ok := kindPayloadType[fields.Kind]; !ok || fields.PayloadType != expected {
		return fmt.Errorf("%w: payload_type %d does not match kind %d", ErrRouting, fields.PayloadType, fields.Kind)
	}
	// 3 chain identity and freshness
	if fields.ChainID != opts.ChainID {
		return fmt.Errorf("%w: chain_id mismatch", ErrChainFresh)
	}
	if fields.IssuedAtUnixMS == 0 || fields.ExpiresAtUnixMS <= fields.IssuedAtUnixMS {
		return fmt.Errorf("%w: freshness bounds", ErrChainFresh)
	}
	if fields.ExpiresAtUnixMS-fields.IssuedAtUnixMS > MaxEnvelopeTTLMS {
		return fmt.Errorf("%w: ttl exceeds %dms", ErrChainFresh, MaxEnvelopeTTLMS)
	}
	if opts.NowUnixMS > fields.ExpiresAtUnixMS {
		return fmt.Errorf("%w: envelope expired", ErrChainFresh)
	}
	// 4 payload digest over the exact received bytes
	digest := PayloadDigest(payload)
	if !bytes.Equal(digest[:], fields.PayloadDigest) {
		return fmt.Errorf("%w: payload_digest mismatch", ErrPayload)
	}
	// 5 current service key binding
	if opts.LookupKey == nil {
		return fmt.Errorf("%w: key lookup is not configured", ErrKeyBinding)
	}
	binding, err := opts.LookupKey(fields.SenderParticipantType, fields.SenderOperatorAddress)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyBinding, err)
	}
	if !binding.Active {
		return fmt.Errorf("%w: service key is not active", ErrKeyBinding)
	}
	if binding.AuthorizationNonce != fields.ServiceAuthorizationNonce {
		return fmt.Errorf("%w: service_authorization_nonce mismatch", ErrKeyBinding)
	}
	if len(binding.PubKeyCompressed) != 33 {
		return fmt.Errorf("%w: service key must be a 33-byte compressed point", ErrKeyBinding)
	}
	// 6 signature over the signing digest, directly
	signingDigest, err := SigningDigest(fields)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStructure, err)
	}
	if err := VerifyDigestSignature(binding.PubKeyCompressed, signingDigest[:], signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	// 7 replay store
	if opts.Replay != nil {
		record := ReplayRecord{
			ChainID:            fields.ChainID,
			SenderOperator:     fields.SenderOperatorAddress,
			AuthorizationNonce: fields.ServiceAuthorizationNonce,
			MessageID:          fields.MessageID,
			Nonce:              fields.Nonce,
			SignDigest:         signingDigest,
			TombstoneUntilMS:   saturatingAdd(fields.ExpiresAtUnixMS, opts.ReplaySafetyMarginMS),
		}
		if err := opts.Replay.StoreOnce(record, opts.NowUnixMS); err != nil {
			return err
		}
	}
	return nil
}

// VerifyDigestSignature checks a 64-byte compact low-S R||S secp256k1
// signature directly against a 32-byte digest. It never hashes the digest
// again, and rejects DER, 65-byte recoverable encodings, zero or overflowing
// scalars and high-S values.
func VerifyDigestSignature(pubKeyCompressed, digest, signature []byte) error {
	if len(digest) != sha256.Size {
		return fmt.Errorf("digest must be %d bytes", sha256.Size)
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("signature must be %d-byte compact R||S, got %d", SignatureSize, len(signature))
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

// saturatingAdd keeps a tombstone deadline from wrapping. The TTL bound limits
// expires_at - issued_at, not how far in the future issued_at itself sits, so an
// envelope near the uint64 ceiling can pass every freshness check and still
// overflow this sum - which would produce a deadline in the past and leave that
// envelope with no replay protection at all.
func saturatingAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}
