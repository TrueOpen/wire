package bus

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cosmos/btcutil/bech32"
)

// Domain is the H_FIELDS_V1 signing domain of this projection. It is V2, not
// V1: TRUEOPEN_BUS_ENVELOPE_V1 names the retired 20-field trueopen-cjson-v1
// projection, and one domain must never cover two different signed field sets.
const Domain = "TRUEOPEN_BUS_ENVELOPE_V2"

// PayloadDomain is the registered H_V1 domain for the exact transmitted
// protobuf payload bytes. V1 names the retired unregistered bare-SHA scheme.
const PayloadDomain = "TRUEOPEN_BUS_PAYLOAD_V2"

const payloadFrameMagic = "TRUEOPEN_FRAME_V1"

// operatorAddressCodecSize is the address-codec byte length the projection
// accepts, matching the cosmos-sdk account address length used by every other
// H_FIELDS_V1 address field.
const operatorAddressCodecSize = 20

// OperatorAddressHRPV1 is the fixed current-chain account/operator HRP for V1.
// It is an acceptance rule and never enters a signing or identity preimage.
const OperatorAddressHRPV1 = "trueopen"

// PayloadDigest is H_V1 over the exact payload bytes as transmitted.
// Senders compute it once over the bytes they publish; receivers compute it
// over the bytes they received, before any decoding. No hop may re-marshal the
// payload to recompute this value.
func PayloadDigest(payload []byte) [32]byte {
	return sha256.Sum256(PayloadPreimage(payload))
}

// PayloadPreimage returns PayloadFrameV1(PayloadDomain, payload). The payload
// object is the opaque byte string itself: semantically equivalent protobuf
// encodings remain different transport publications.
func PayloadPreimage(payload []byte) []byte {
	domain := []byte(PayloadDomain)
	preimage := make([]byte, 0, len(payloadFrameMagic)+4+len(domain)+8+len(payload))
	preimage = append(preimage, payloadFrameMagic...)
	preimage = append(preimage, u32be(uint32(len(domain)))...)
	preimage = append(preimage, domain...)
	preimage = append(preimage, u64be(uint64(len(payload)))...)
	preimage = append(preimage, payload...)
	return preimage
}

// SigningDigest builds the H_FIELDS_V1 preimage of the 13 projection fields
// under Domain and returns its SHA-256. The service key signs this digest
// directly; there is no second hash.
//
// Typed encodings follow the frozen framing table: uint32/enum -> 4-byte
// big-endian, uint64 -> 8-byte big-endian, string -> strict UTF-8 bytes,
// bytes -> raw, operator address -> the 20 bech32-decoded address-codec bytes
// (never the bech32 text).
func SigningDigest(fields Fields) ([32]byte, error) {
	preimage, err := SigningPreimage(fields)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// SigningPreimage returns the full H_FIELDS_V1 frame the digest is computed
// over. Exposed so vectors and debugging tools can compare byte-by-byte; the
// preimage itself is never transmitted or stored.
func SigningPreimage(fields Fields) ([]byte, error) {
	if err := validateProjection(fields); err != nil {
		return nil, err
	}
	operator, err := operatorAddressCodecBytesForHRP(fields.SenderOperatorAddress, OperatorAddressHRPV1)
	if err != nil {
		return nil, err
	}
	return frame(
		[]byte(Domain),
		u32be(fields.SchemaVersion),
		[]byte(fields.ChainID),
		[]byte(fields.Subject),
		u32be(uint32(fields.Kind)),
		u32be(uint32(fields.SenderParticipantType)),
		operator,
		u64be(fields.ServiceAuthorizationNonce),
		[]byte(fields.MessageID),
		fields.Nonce,
		u64be(fields.IssuedAtUnixMS),
		u64be(fields.ExpiresAtUnixMS),
		u32be(uint32(fields.PayloadType)),
		fields.PayloadDigest,
	), nil
}

// validateProjection rejects anything the frozen projection cannot encode
// unambiguously. It is deliberately strict: a field the sender got wrong must
// fail here, not produce a digest no other implementation reproduces.
func validateProjection(fields Fields) error {
	switch {
	case fields.SchemaVersion != SchemaVersion:
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	case fields.ChainID == "" || !utf8.ValidString(fields.ChainID):
		return errors.New("chain_id must be non-empty valid UTF-8")
	case fields.Subject == "" || !utf8.ValidString(fields.Subject):
		return errors.New("subject must be non-empty valid UTF-8")
	case fields.MessageID == "" || !utf8.ValidString(fields.MessageID):
		return errors.New("message_id must be non-empty valid UTF-8")
	case len(fields.Nonce) != NonceSize:
		return fmt.Errorf("nonce must be exactly %d bytes", NonceSize)
	case len(fields.PayloadDigest) != sha256.Size:
		return fmt.Errorf("payload_digest must be exactly %d bytes", sha256.Size)
	}
	if _, ok := kindPayloadType[fields.Kind]; !ok {
		return fmt.Errorf("unknown kind %d", fields.Kind)
	}
	if fields.PayloadType == PayloadTypeUnspecified {
		return errors.New("payload_type must not be unspecified")
	}
	if fields.SenderParticipantType != ParticipantCortex && fields.SenderParticipantType != ParticipantBuilder {
		return fmt.Errorf("unknown sender_participant_type %d", fields.SenderParticipantType)
	}
	return nil
}

// OperatorAddressCodecBytes decodes a canonical bech32 operator address to its
// 20 address-codec bytes, the form every H_FIELDS_V1 address field frames.
// The bech32 human-readable prefix does not enter the preimage; re-encoding
// the returned bytes with the chain prefix must reproduce the input exactly.
func OperatorAddressCodecBytes(address string) ([]byte, error) {
	_, data, err := decodeCanonicalOperatorAddress(address)
	return data, err
}

// operatorAddressCodecBytesForHRP applies the proof-only current-chain HRP gate.
// OperatorAddressCodecBytes intentionally remains HRP-agnostic because existing
// signing and identity preimages commit to codec bytes, not Bech32 namespace.
func operatorAddressCodecBytesForHRP(address, expectedHRP string) ([]byte, error) {
	if expectedHRP == "" || strings.ToLower(expectedHRP) != expectedHRP {
		return nil, fmt.Errorf("expected HRP must be non-empty lowercase, got %q", expectedHRP)
	}
	hrp, data, err := decodeCanonicalOperatorAddress(address)
	if err != nil {
		return nil, err
	}
	if hrp != expectedHRP {
		return nil, fmt.Errorf("operator address HRP %q does not match expected HRP %q", hrp, expectedHRP)
	}
	return data, nil
}

func decodeCanonicalOperatorAddress(address string) (string, []byte, error) {
	hrp, data, err := bech32.DecodeToBase256(address)
	if err != nil {
		return "", nil, fmt.Errorf("operator address is not canonical bech32: %w", err)
	}
	if len(data) != operatorAddressCodecSize {
		return "", nil, fmt.Errorf("operator address must decode to %d bytes, got %d", operatorAddressCodecSize, len(data))
	}
	// bech32 accepts an all-uppercase spelling of the same address, and the
	// signing projection frames only these decoded bytes, so without this check
	// one signature would be valid for two different sender_operator_address
	// strings. The replay keys and EquivocationPreconditions no longer depend on
	// the text - both compare these bytes - but the text still reaches key lookup
	// and every consumer that stores or displays the address, and one identity
	// with two spellings there is a defect of its own.
	//
	// This pins the spelling under a given prefix; it deliberately does not pin
	// the current-chain prefix. The proof-only verifier applies the fixed
	// OperatorAddressHRPV1 gate before key lookup, while signing and identity
	// projections continue to frame only codec bytes.
	canonical, err := bech32.EncodeFromBase256(hrp, data)
	if err != nil {
		return "", nil, fmt.Errorf("operator address does not re-encode: %w", err)
	}
	if canonical != address {
		return "", nil, fmt.Errorf("operator address %q is not the canonical spelling of its own bytes, %q", address, canonical)
	}
	return hrp, data, nil
}

// frame is CanonicalFrameBytes: every part is prefixed with its 8-byte
// big-endian length, in order, with no separators and no trailing bytes.
func frame(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += 8 + len(part)
	}
	framed := make([]byte, 0, total)
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		framed = append(framed, length[:]...)
		framed = append(framed, part...)
	}
	return framed
}

func u32be(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.BigEndian.PutUint32(encoded, value)
	return encoded
}

func u64be(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}
