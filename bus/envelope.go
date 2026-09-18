// Package bus is the canonical Go implementation of the
// TRUEOPEN_BUS_ENVELOPE_V2 signing projection, verification order and replay
// keys for the trueopen.* NATS task-control wire (TrueOpen/nexus#52,
// proto/bus/v1).
//
// It is contract logic only: pure functions over plain field values, with no
// dependency on generated protobuf code, NATS, storage engines or chain
// clients. Consumers (nexus, cortex) map their generated BusEnvelopeV1 into
// Fields and inject key lookup and replay storage. Both consumers MUST use
// this package rather than re-implementing the projection; the cross-language
// vectors under testdata/ are the compatibility anchor for any non-Go
// implementation.
package bus

// Enum numbers below mirror proto/bus/v1/envelope.proto and are frozen
// there; this file never invents numbering.

// Kind values mirror bus.v1.BusMessageKind.
const (
	KindUnspecified              int32 = 0
	KindOrderBroadcast           int32 = 1
	KindWorkerHandraise          int32 = 2
	KindWorkerAssignmentNotify   int32 = 3
	KindOutputAvailable          int32 = 4
	KindOpenVerify               int32 = 5
	KindVerifierHandraise        int32 = 6
	KindVerifierAssignmentNotify int32 = 7
	KindVerifyResult             int32 = 8
)

// PayloadType values mirror bus.v1.BusPayloadType.
const (
	PayloadTypeUnspecified                int32 = 0
	PayloadTypeOrderBroadcastV1           int32 = 1
	PayloadTypeWorkerHandraiseV1          int32 = 2
	PayloadTypeWorkerAssignmentNotifyV1   int32 = 3
	PayloadTypeOutputAvailableV1          int32 = 4
	PayloadTypeOpenVerifyV1               int32 = 5
	PayloadTypeVerifierHandraiseV1        int32 = 6
	PayloadTypeVerifierAssignmentNotifyV1 int32 = 7
	PayloadTypeVerifyResultV1             int32 = 8
)

// kindPayloadType is the frozen kind -> payload_type mapping documented on
// BusPayloadType in envelope.proto. Receivers reject any pair outside it.
var kindPayloadType = map[int32]int32{
	KindOrderBroadcast:           PayloadTypeOrderBroadcastV1,
	KindWorkerHandraise:          PayloadTypeWorkerHandraiseV1,
	KindWorkerAssignmentNotify:   PayloadTypeWorkerAssignmentNotifyV1,
	KindOutputAvailable:          PayloadTypeOutputAvailableV1,
	KindOpenVerify:               PayloadTypeOpenVerifyV1,
	KindVerifierHandraise:        PayloadTypeVerifierHandraiseV1,
	KindVerifierAssignmentNotify: PayloadTypeVerifierAssignmentNotifyV1,
	KindVerifyResult:             PayloadTypeVerifyResultV1,
}

// PayloadTypeForKind returns the frozen payload type for a kind, or false for
// an unknown kind.
func PayloadTypeForKind(kind int32) (int32, bool) {
	payloadType, ok := kindPayloadType[kind]
	return payloadType, ok
}

// ParticipantType values mirror shared.v1.ParticipantType.
const (
	ParticipantUnspecified int32 = 0
	ParticipantCortex      int32 = 1
	ParticipantBuilder     int32 = 2
)

// NonceSize is the frozen envelope nonce length in bytes.
const NonceSize = 32

// SignatureSize is the frozen compact low-S R||S signature length in bytes.
const SignatureSize = 64

// SchemaVersion is the only accepted BusEnvelopeV1.schema_version. It is a
// constant rather than a literal at each check so the projection, the live
// verifier and the evidence verifier cannot disagree about the generation.
const SchemaVersion uint32 = 1

// MaxEnvelopeBytes is the fixed encoded BusEnvelopeV1 size limit. It is a
// protocol constant, not a receiver-local deployment setting.
const MaxEnvelopeBytes = 1_048_576

// MaxEnvelopeTTLMS is the maximum expires_at - issued_at interval accepted by
// every sender, live receiver and evidence verifier.
const MaxEnvelopeTTLMS uint64 = 60_000

// Fields is the signed projection of BusEnvelopeV1: fields 1..12 plus
// payload_digest (field 14), in proto field-number order. The payload body
// (field 13) and service_signature (field 15) never enter the projection; the
// payload is bound through PayloadDigest.
type Fields struct {
	SchemaVersion             uint32 // 1, must be 1
	ChainID                   string // 2
	Subject                   string // 3
	Kind                      int32  // 4
	SenderParticipantType     int32  // 5
	SenderOperatorAddress     string // 6, canonical bech32
	ServiceAuthorizationNonce uint64 // 7
	MessageID                 string // 8, UUIDv7 text
	Nonce                     []byte // 9, exactly 32 bytes
	IssuedAtUnixMS            uint64 // 10
	ExpiresAtUnixMS           uint64 // 11
	PayloadType               int32  // 12
	PayloadDigest             []byte // 14, exactly 32 bytes: H_V1(PayloadDomain, transmitted payload bytes)
}
