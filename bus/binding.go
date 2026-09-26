package bus

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// BindingDomain is the H_FIELDS_V1 signing domain of the NATS user binding
// declaration. It is the service key's second
// signing use next to TRUEOPEN_BUS_ENVELOPE_V2 and therefore its own domain: one
// domain never interprets two projections.
const BindingDomain = "TRUEOPEN_NATS_USER_BINDING_V1"

// BindingSchemaVersion is the only schema_version NatsUserBindingV1 accepts.
const BindingSchemaVersion uint32 = 1

// MaxBindingBytes bounds the encoded NatsUserBindingV1. It is checked before the
// token is decoded and before the protobuf bytes are parsed.
const MaxBindingBytes = 1024

// BindingTokenPrefix distinguishes this token generation inside the NATS
// CONNECT auth_token field.
const BindingTokenPrefix = "trueopen-nub1."

// natsUserPubkeyLength is the text length of every nkey public key: 35 bytes
// (1 prefix + 32 key + 2 CRC) in unpadded base32 is 56 characters.
const natsUserPubkeyLength = 56

// natsUserPrefixByte is the nkeys prefix byte of a user public key, the value
// that makes the text start with "U".
const natsUserPrefixByte = 20 << 3

// ErrBinding is the class every NatsUserBindingV1 decode, projection and token
// failure wraps, so a caller can tell a malformed declaration from a chain
// lookup or signature failure with one errors.Is.
var ErrBinding = errors.New("bus: nats user binding")

// BindingFields is the signed projection of NatsUserBindingV1: fields 1..7 in
// proto field-number order. Field 8 service_signature never enters it.
type BindingFields struct {
	SchemaVersion             uint32 // 1, must be 1
	ChainID                   string // 2
	ParticipantType           int32  // 3, must be ParticipantCortex
	OperatorAddress           string // 4, canonical bech32 with the current-chain HRP
	ServiceAuthorizationNonce uint64 // 5
	NATSUserPubkey            string // 6, nkey user public key text
	IssuedAtUnixMS            uint64 // 7
}

// DecodedBinding is a strictly decoded NatsUserBindingV1.
type DecodedBinding struct {
	Fields    BindingFields
	Signature []byte
	RawSize   int
}

// BindingSigningDigest builds the H_FIELDS_V1 preimage of the seven projection
// fields under BindingDomain and returns its SHA-256. The service key signs
// this digest directly.
func BindingSigningDigest(fields BindingFields) ([32]byte, error) {
	preimage, err := BindingSigningPreimage(fields)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// BindingSigningPreimage returns the full H_FIELDS_V1 frame the binding digest
// is computed over. Exposed for vectors and debugging; never transmitted.
func BindingSigningPreimage(fields BindingFields) ([]byte, error) {
	if err := validateBinding(fields); err != nil {
		return nil, err
	}
	operator, err := operatorAddressCodecBytesForHRP(fields.OperatorAddress, OperatorAddressHRPV1)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	return frame(
		[]byte(BindingDomain),
		u32be(fields.SchemaVersion),
		[]byte(fields.ChainID),
		u32be(uint32(fields.ParticipantType)),
		operator,
		u64be(fields.ServiceAuthorizationNonce),
		[]byte(fields.NATSUserPubkey),
		u64be(fields.IssuedAtUnixMS),
	), nil
}

// validateBinding rejects, rather than repairs, every input this contract lists as
// unencodable. A field the sender got wrong must fail here, not produce a
// digest no other implementation reproduces.
func validateBinding(fields BindingFields) error {
	switch {
	case fields.SchemaVersion != BindingSchemaVersion:
		return fmt.Errorf("%w: schema_version must be %d", ErrBinding, BindingSchemaVersion)
	case fields.ChainID == "" || !utf8.ValidString(fields.ChainID):
		return fmt.Errorf("%w: chain_id must be non-empty valid UTF-8", ErrBinding)
	case fields.ParticipantType != ParticipantCortex:
		return fmt.Errorf("%w: participant_type must be CORTEX (%d), got %d", ErrBinding, ParticipantCortex, fields.ParticipantType)
	}
	if err := ValidateNATSUserPublicKey(fields.NATSUserPubkey); err != nil {
		return err
	}
	return nil
}

// ValidateNATSUserPublicKey checks that text is a well-formed nkey user public
// key: 56 characters of unpadded RFC 4648 base32 that decode to the user prefix
// byte, 32 key bytes and a valid CRC-16/XMODEM trailer. It does not check that
// anyone holds the key; possession is proven by the NATS nonce signature.
func ValidateNATSUserPublicKey(text string) error {
	if len(text) != natsUserPubkeyLength {
		return fmt.Errorf("%w: nats_user_pubkey must be %d characters, got %d", ErrBinding, natsUserPubkeyLength, len(text))
	}
	if !strings.HasPrefix(text, "U") {
		return fmt.Errorf("%w: nats_user_pubkey must be a user key starting with U", ErrBinding)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(text)
	if err != nil {
		return fmt.Errorf("%w: nats_user_pubkey is not base32: %v", ErrBinding, err)
	}
	if len(raw) != 35 || raw[0] != natsUserPrefixByte {
		return fmt.Errorf("%w: nats_user_pubkey does not carry the user prefix byte", ErrBinding)
	}
	body, trailer := raw[:33], raw[33:]
	if got := crc16XModem(body); got != uint16(trailer[0])|uint16(trailer[1])<<8 {
		return fmt.Errorf("%w: nats_user_pubkey checksum mismatch", ErrBinding)
	}
	return nil
}

// crc16XModem is the CRC-16/XMODEM nkeys appends little-endian to every key:
// polynomial 0x1021, initial value 0, no reflection, no final xor.
func crc16XModem(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// DecodeBinding strictly decodes one NatsUserBindingV1 and returns its
// projection and signature. It applies the size bound, the pinned field table
// and the signature width; it does not verify the signature or consult the
// chain, which are the callout service's later steps.
func DecodeBinding(raw []byte) (DecodedBinding, error) {
	if len(raw) == 0 || len(raw) > MaxBindingBytes {
		return DecodedBinding{}, fmt.Errorf("%w: encoded size must be 1..%d bytes, got %d", ErrBinding, MaxBindingBytes, len(raw))
	}
	message, err := strictDecodeWithLimit(msgNatsUserBindingV1, raw, MaxBindingBytes)
	if err != nil {
		return DecodedBinding{}, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	schemaVersion, err := message.uint32At(msgNatsUserBindingV1, 1)
	if err != nil {
		return DecodedBinding{}, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	participantType, err := message.int32At(msgNatsUserBindingV1, 3)
	if err != nil {
		return DecodedBinding{}, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	signature := message.bytesAt(8)
	if len(signature) != SignatureSize {
		return DecodedBinding{}, fmt.Errorf("%w: service_signature is %d bytes, want %d", ErrBinding, len(signature), SignatureSize)
	}
	out := DecodedBinding{
		Fields: BindingFields{
			SchemaVersion:             schemaVersion,
			ChainID:                   message.stringAt(2),
			ParticipantType:           participantType,
			OperatorAddress:           message.stringAt(4),
			ServiceAuthorizationNonce: message.uint64At(5),
			NATSUserPubkey:            message.stringAt(6),
			IssuedAtUnixMS:            message.uint64At(7),
		},
		Signature: signature,
		RawSize:   len(raw),
	}
	if err := validateBinding(out.Fields); err != nil {
		return DecodedBinding{}, err
	}
	if _, err := operatorAddressCodecBytesForHRP(out.Fields.OperatorAddress, OperatorAddressHRPV1); err != nil {
		return DecodedBinding{}, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	return out, nil
}

// EncodeBinding serializes a binding as the protobuf bytes NatsUserBindingV1
// declares, fields in number order, proto3 default values omitted. It exists
// so a Cortex without generated code and the conformance vectors produce the
// same bytes; a generated encoder produces identical output for these fields.
func EncodeBinding(fields BindingFields, signature []byte) ([]byte, error) {
	if err := validateBinding(fields); err != nil {
		return nil, err
	}
	if _, err := operatorAddressCodecBytesForHRP(fields.OperatorAddress, OperatorAddressHRPV1); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	if len(signature) != SignatureSize {
		return nil, fmt.Errorf("%w: service_signature is %d bytes, want %d", ErrBinding, len(signature), SignatureSize)
	}
	var out []byte
	out = appendVarintField(out, 1, uint64(fields.SchemaVersion))
	out = appendBytesField(out, 2, []byte(fields.ChainID))
	out = appendVarintField(out, 3, uint64(uint32(fields.ParticipantType)))
	out = appendBytesField(out, 4, []byte(fields.OperatorAddress))
	out = appendVarintField(out, 5, fields.ServiceAuthorizationNonce)
	out = appendBytesField(out, 6, []byte(fields.NATSUserPubkey))
	out = appendVarintField(out, 7, fields.IssuedAtUnixMS)
	out = appendBytesField(out, 8, signature)
	if len(out) > MaxBindingBytes {
		return nil, fmt.Errorf("%w: encoded size %d exceeds %d bytes", ErrBinding, len(out), MaxBindingBytes)
	}
	return out, nil
}

// EncodeBindingToken wraps encoded NatsUserBindingV1 bytes as the NATS CONNECT
// auth_token: BindingTokenPrefix followed by unpadded base64url.
func EncodeBindingToken(encoded []byte) string {
	return BindingTokenPrefix + base64.RawURLEncoding.EncodeToString(encoded)
}

// DecodeBindingToken reverses EncodeBindingToken. The prefix and the size bound
// are checked before any base64 or protobuf work is done.
func DecodeBindingToken(token string) ([]byte, error) {
	if !strings.HasPrefix(token, BindingTokenPrefix) {
		return nil, fmt.Errorf("%w: token does not start with %q", ErrBinding, BindingTokenPrefix)
	}
	body := token[len(BindingTokenPrefix):]
	if base64.RawURLEncoding.DecodedLen(len(body)) > MaxBindingBytes {
		return nil, fmt.Errorf("%w: token exceeds %d encoded bytes", ErrBinding, MaxBindingBytes)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("%w: token is not unpadded base64url: %v", ErrBinding, err)
	}
	if len(raw) == 0 || len(raw) > MaxBindingBytes {
		return nil, fmt.Errorf("%w: encoded size must be 1..%d bytes, got %d", ErrBinding, MaxBindingBytes, len(raw))
	}
	return raw, nil
}

// VerifyBindingSignature checks the binding's compact low-S signature against
// the compressed current service key the verifier resolved on chain. The
// caller has already established that the binding is ACTIVE at the nonce the
// declaration carries; this is the step after that lookup.
func VerifyBindingSignature(fields BindingFields, signature, pubKeyCompressed []byte) error {
	digest, err := BindingSigningDigest(fields)
	if err != nil {
		return err
	}
	return VerifyDigestSignature(pubKeyCompressed, digest[:], signature)
}

func appendVarintField(out []byte, number uint32, value uint64) []byte {
	if value == 0 {
		return out
	}
	out = appendUvarint(out, uint64(number)<<3|wireVarint)
	return appendUvarint(out, value)
}

func appendBytesField(out []byte, number uint32, value []byte) []byte {
	if len(value) == 0 {
		return out
	}
	out = appendUvarint(out, uint64(number)<<3|wireBytes)
	out = appendUvarint(out, uint64(len(value)))
	return append(out, value...)
}

func appendUvarint(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}
