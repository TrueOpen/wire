package bus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// sha256Sum is a named wrapper so a test can recompute a digest through the
// same call the projection uses, instead of asserting against a value the
// projection produced.
func sha256Sum(preimage []byte) [32]byte { return sha256.Sum256(preimage) }

// Subject prefixes of the trueopen.* task-control subjects. keeper_api_contract.md §5.5
// derives the expected subject from the typed payload and then compares it with
// the signed subject, so these are the only place the templates appear: a second
// copy in a caller would be a second authority on what the signer committed to.
const (
	subjectTaskOpenPrefix                  = "trueopen.task.open."
	subjectWorkerHandraisePrefix           = "trueopen.handraise.worker."
	subjectWorkerAssignmentPrefix          = "trueopen.worker-assignment."
	subjectOutputAvailablePrefix           = "trueopen.output-avail."
	subjectOpenVerifyPrefix                = "trueopen.verify.open."
	subjectVerifierHandraisePrefix         = "trueopen.handraise.verifier."
	subjectVerifierAssignmentPrefix        = "trueopen.verifier-assignment."
	subjectVerifyResultPrefix              = "trueopen.verify-result."
	domainTaskIDV1                  string = "TRUEOPEN_TASK_ID_V1"
)

// BusActionScopeV2 is the plain business projection of a decoded payload, fixed
// by keeper_api_contract.md §5.5. It is deliberately not a protobuf message, not a
// Store row and not an API type: it exists so a Task Keeper can look up Task
// authority without the Bus generated package entering its import graph.
//
// The optional fields are absent, not zero, when the payload does not carry
// them. §5.5 is explicit that a missing optional scope value must be loaded from
// the Task authority the table names and must never be guessed from a field name
// or copied from an unrelated payload - so a nil TaskHash here means "ask the
// Task authority", never "the empty hash".
type BusActionScopeV2 struct {
	Kind            int32
	PayloadType     int32
	ExpectedSubject string
	// TaskID is raw32 and always present: every kind either carries it or, for
	// ORDER_BROADCAST, derives it from the signed order.
	TaskID []byte
	// TaskHash is raw32 when the payload carries it. It is absent for
	// VERIFIER_HANDRAISE and VERIFY_RESULT, which §5.5 loads from Task authority,
	// and for ORDER_BROADCAST - see OrderBytes on DecodedEnvelope.
	TaskHash []byte
	// ModelID is absent unless the payload carries it.
	ModelID *string
	// VerifyRound is absent unless the payload carries it.
	VerifyRound *uint32
	// PayloadActor is the canonical address the payload attributes the action to.
	// It is absent for VERIFIER_ASSIGNMENT_NOTIFY, whose payload names a set
	// rather than one actor.
	PayloadActor *string
}

// DecodedEnvelope is what the import-leaf decoder returns: the plain signing
// fields, the exact payload bytes as transmitted, the raw signature, and the
// business scope. keeper_api_contract.md §5.5 fixes this return shape so that Node
// keeps no second envelope struct, kind numbering, payload map or signing helper.
type DecodedEnvelope struct {
	Fields Fields
	// Payload is the exact transmitted bytes, aliasing the caller's input. The
	// payload digest is computed over these bytes and no hop may re-marshal them,
	// so the decoder hands back the original and never a re-encoding.
	Payload   []byte
	Signature []byte
	// RawSize is the encoded envelope length the size bound was checked against.
	RawSize int
	Scope   BusActionScopeV2
	// OrderBytes is the exact serialized task.v1.TaskOrderV2 of an
	// ORDER_BROADCAST payload, and nil for every other kind.
	//
	// §5.5 derives that kind's task_hash by recomputing TRUEOPEN_TASK_ORDER_V2 over
	// the canonical TaskOrderV2 projection. That projection is a 25-field
	// registered domain of its own, covering Amount, GenerationParamsV1 and
	// DeadlinePolicyV1 canonical forms that this package does not implement, and a
	// guessed projection would produce a confidently wrong task_hash - worse than
	// an absent one, because it would compare unequal against the authority and
	// look like tampering. So the decoder hands over the exact bytes and leaves
	// Scope.TaskHash absent; the caller recomputes with its own registered
	// TRUEOPEN_TASK_ORDER_V2 implementation over these bytes, not over a re-encoding.
	OrderBytes []byte
}

// DecodeEnvelope strictly decodes an exact serialized bus.v1.BusEnvelopeV1
// and projects its payload into a BusActionScopeV2.
//
// It decodes and projects only. Nothing here consults a key, a clock, a replay
// store or Task state: VerifyEvidence layers those on top, and keeping them
// apart is what lets one decoder serve both the live receiver profile and the
// chain proof-only profile without either inheriting the other's assumptions.
func DecodeEnvelope(raw []byte) (DecodedEnvelope, error) {
	return decodeEnvelope(raw, true)
}

func decodeEnvelope(raw []byte, project bool) (DecodedEnvelope, error) {
	// Step 1 of both profiles: the size bound is a protocol constant checked
	// before protobuf parsing or allocation, not a receiver-local setting.
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return DecodedEnvelope{}, fmt.Errorf("%w: envelope size must be 1..%d bytes, got %d",
			ErrDecode, MaxEnvelopeBytes, len(raw))
	}
	message, err := strictDecode(msgBusEnvelopeV1, raw)
	if err != nil {
		return DecodedEnvelope{}, err
	}

	schemaVersion, err := message.uint32At(msgBusEnvelopeV1, 1)
	if err != nil {
		return DecodedEnvelope{}, err
	}
	kind, err := message.int32At(msgBusEnvelopeV1, 4)
	if err != nil {
		return DecodedEnvelope{}, err
	}
	participantType, err := message.int32At(msgBusEnvelopeV1, 5)
	if err != nil {
		return DecodedEnvelope{}, err
	}
	payloadType, err := message.int32At(msgBusEnvelopeV1, 12)
	if err != nil {
		return DecodedEnvelope{}, err
	}
	nonce, err := message.hash32At(msgBusEnvelopeV1, 9)
	if err != nil {
		return DecodedEnvelope{}, err
	}
	payloadDigest, err := message.hash32At(msgBusEnvelopeV1, 14)
	if err != nil {
		return DecodedEnvelope{}, err
	}

	payload := message.bytesAt(13)
	if len(payload) == 0 {
		return DecodedEnvelope{}, fmt.Errorf("%w: payload (field 13) is required", ErrDecode)
	}
	signature := message.bytesAt(15)
	if len(signature) != SignatureSize {
		return DecodedEnvelope{}, fmt.Errorf("%w: service_signature is %d bytes, want %d",
			ErrDecode, len(signature), SignatureSize)
	}

	out := DecodedEnvelope{
		Fields: Fields{
			SchemaVersion:             schemaVersion,
			ChainID:                   message.stringAt(2),
			Subject:                   message.stringAt(3),
			Kind:                      kind,
			SenderParticipantType:     participantType,
			SenderOperatorAddress:     message.stringAt(6),
			ServiceAuthorizationNonce: message.uint64At(7),
			MessageID:                 message.stringAt(8),
			Nonce:                     nonce,
			IssuedAtUnixMS:            message.uint64At(10),
			ExpiresAtUnixMS:           message.uint64At(11),
			PayloadType:               payloadType,
			PayloadDigest:             payloadDigest,
		},
		Payload:   payload,
		Signature: signature,
		RawSize:   len(raw),
	}

	// The digest is recomputed over the received bytes here rather than being
	// trusted from field 14, because field 14 is what the signature covers: if
	// the two disagree, the payload on the wire is not the payload that was
	// signed, and every later check would be examining the wrong bytes.
	if got := PayloadDigest(payload); string(got[:]) != string(payloadDigest) {
		return DecodedEnvelope{}, fmt.Errorf("%w: payload_digest does not match H_V1(%s, payload)",
			ErrDecode, PayloadDomain)
	}

	if !project {
		return out, nil
	}
	scope, orderBytes, err := projectScope(kind, payloadType, payload)
	if err != nil {
		return DecodedEnvelope{}, err
	}
	out.Scope = scope
	out.OrderBytes = orderBytes
	return out, nil
}

// DecodeEnvelopeHeader is DecodeEnvelope without the typed payload projection.
//
// The split exists because the two happen at different points in the verified
// order. keeper_api_contract.md §5.5 decodes the typed payload at step 6, after the
// signature has verified at step 5, and 07-task_builder_coordination.md §7.3 step 8 says
// the same for the live profile. Doing it earlier does not change which
// envelopes are accepted, but it changes how a rejection reads: an envelope with
// a valid signature and a malformed payload would come back as ErrDecode, which
// this package defines as material that is nobody's fault, when in fact it is
// signed and therefore attributable. Callers that need the spec order use this
// and then ProjectPayload; callers that only want a decoded envelope use
// DecodeEnvelope.
//
// Scope and OrderBytes are zero on the returned value.
func DecodeEnvelopeHeader(raw []byte) (DecodedEnvelope, error) {
	return decodeEnvelope(raw, false)
}

// ProjectPayload projects an already-decoded envelope's payload into its action
// scope. It is separate from DecodeEnvelopeHeader so the caller controls when it
// runs relative to signature verification.
func (d DecodedEnvelope) ProjectPayload() (BusActionScopeV2, []byte, error) {
	return projectScope(d.Fields.Kind, d.Fields.PayloadType, d.Payload)
}

// projectScope implements the kind -> field-path -> Subject table of
// keeper_api_contract.md §5.5. The field numbers come from the pinned tables in
// prototable.go, which are checked against the .proto sources, so nothing here
// resolves a field by guessing at its name.
func projectScope(kind, payloadType int32, payload []byte) (BusActionScopeV2, []byte, error) {
	expected, ok := kindPayloadType[kind]
	if !ok {
		return BusActionScopeV2{}, nil, fmt.Errorf("%w: unknown kind %d", ErrDecode, kind)
	}
	if payloadType != expected {
		return BusActionScopeV2{}, nil, fmt.Errorf("%w: kind %d requires payload_type %d, got %d",
			ErrDecode, kind, expected, payloadType)
	}

	scope := BusActionScopeV2{Kind: kind, PayloadType: payloadType}
	switch kind {
	case KindOrderBroadcast:
		return projectOrderBroadcast(scope, payload)
	case KindWorkerHandraise:
		return projectFromTable(scope, payload, msgWorkerHandraiseV1, subjectWorkerHandraisePrefix, scopePaths{
			taskID: 3, taskHash: 4, modelID: 5, memberRef: 7,
		})
	case KindWorkerAssignmentNotify:
		return projectFromTable(scope, payload, msgWorkerAssignmentNotifyV1, subjectWorkerAssignmentPrefix, scopePaths{
			taskID: 1, taskHash: 2, actor: 3,
		})
	case KindOutputAvailable:
		return projectFromTable(scope, payload, msgOutputAvailableV1, subjectOutputAvailablePrefix, scopePaths{
			taskID: 1, taskHash: 2, actor: 4,
		})
	case KindOpenVerify:
		return projectFromTable(scope, payload, msgOpenVerifyV1, subjectOpenVerifyPrefix, scopePaths{
			taskID: 1, taskHash: 2, modelID: 3, actor: 7, verifyRound: 8,
		})
	case KindVerifierHandraise:
		// task_hash is deliberately not read: §5.5 loads it from Task authority
		// for this kind, and VerifierHandraiseV1 does not carry one.
		return projectFromTable(scope, payload, msgVerifierHandraiseV1, subjectVerifierHandraisePrefix, scopePaths{
			taskID: 3, verifyRound: 4, modelID: 7, memberRef: 9,
		})
	case KindVerifierAssignmentNotify:
		// The payload names a selected set rather than one actor, so there is no
		// payload_actor to project.
		return projectFromTable(scope, payload, msgVerifierAssignmentNotifyV1, subjectVerifierAssignmentPrefix, scopePaths{
			taskID: 1, taskHash: 2, verifyRound: 3,
		})
	case KindVerifyResult:
		// task_hash and model_id come from Task authority for this kind.
		return projectFromTable(scope, payload, msgResultReceiptV2, subjectVerifyResultPrefix, scopePaths{
			taskID: 3, verifyRound: 4, actor: 5,
		})
	default:
		return BusActionScopeV2{}, nil, fmt.Errorf("%w: kind %d has no scope projection", ErrDecode, kind)
	}
}

// scopePaths names the field numbers one payload type contributes to the scope.
// Zero means "this payload does not carry that value", which is how the table's
// deliberate absences are expressed rather than by a comment.
type scopePaths struct {
	taskID      uint32
	taskHash    uint32
	modelID     uint32
	verifyRound uint32
	actor       uint32
	// memberRef is a CandidateMemberRefV1 field whose operator_address is the
	// actor. The two handraise payloads carry the actor one level down.
	memberRef uint32
}

func projectFromTable(scope BusActionScopeV2, payload []byte, message, subjectPrefix string, paths scopePaths) (BusActionScopeV2, []byte, error) {
	decodedPayload, err := strictDecode(message, payload)
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}

	taskID, err := decodedPayload.hash32At(message, paths.taskID)
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}
	scope.TaskID = taskID
	scope.ExpectedSubject = subjectPrefix + hex.EncodeToString(taskID)

	if paths.taskHash != 0 {
		taskHash, err := decodedPayload.hash32At(message, paths.taskHash)
		if err != nil {
			return BusActionScopeV2{}, nil, err
		}
		scope.TaskHash = taskHash
	}
	if paths.modelID != 0 {
		modelID := decodedPayload.stringAt(paths.modelID)
		if modelID == "" {
			return BusActionScopeV2{}, nil, fmt.Errorf("%w: %s field %d model_id is empty",
				ErrDecode, message, paths.modelID)
		}
		scope.ModelID = &modelID
	}
	if paths.verifyRound != 0 {
		round, err := decodedPayload.uint32At(message, paths.verifyRound)
		if err != nil {
			return BusActionScopeV2{}, nil, err
		}
		if round == 0 {
			return BusActionScopeV2{}, nil, fmt.Errorf("%w: %s field %d verify_round must be greater than 0",
				ErrDecode, message, paths.verifyRound)
		}
		scope.VerifyRound = &round
	}

	actor, err := projectActor(decodedPayload, message, paths)
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}
	scope.PayloadActor = actor
	return scope, nil, nil
}

// candidateMemberOperatorField is CandidateMemberRefV1.operator_address. It is a
// constant because the two handraise payloads reach the actor through that
// message, and a wrong number here would attribute an action to the wrong
// participant rather than fail - the one error in this file that would be
// invisible instead of loud.
const candidateMemberOperatorField uint32 = 4

// projectActor resolves the address the payload attributes the action to.
//
// Three shapes exist and they are mutually exclusive: the actor is a field of
// the payload, or it is one level down inside a CandidateMemberRefV1, or the
// payload has no single actor at all (VERIFIER_ASSIGNMENT_NOTIFY names a set).
// Returning nil for the third is what keeps "no actor in this payload" distinct
// from "the empty address".
func projectActor(payload decoded, message string, paths scopePaths) (*string, error) {
	if paths.actor != 0 && paths.memberRef != 0 {
		// Unreachable through projectScope, and it stays that way loudly: a table
		// naming both would silently pick one and attribute the action to it.
		return nil, fmt.Errorf("%w: %s names both a direct actor field and a member ref", ErrDecode, message)
	}

	holder, holderMessage, field := payload, message, paths.actor
	if paths.memberRef != 0 {
		member, err := strictDecode(msgCandidateMemberRefV1, payload.bytesAt(paths.memberRef))
		if err != nil {
			return nil, err
		}
		holder, holderMessage, field = member, msgCandidateMemberRefV1, candidateMemberOperatorField
	}
	if field == 0 {
		return nil, nil
	}

	actor := holder.stringAt(field)
	if actor == "" {
		return nil, fmt.Errorf("%w: %s field %d operator address is empty", ErrDecode, holderMessage, field)
	}
	return &actor, nil
}

// projectOrderBroadcast is the one kind whose task_id is derived rather than
// carried: §5.5 recomputes it from signed_order.order per TaskOrder §3.
func projectOrderBroadcast(scope BusActionScopeV2, payload []byte) (BusActionScopeV2, []byte, error) {
	broadcast, err := strictDecode(msgOrderBroadcastV1, payload)
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}
	signedOrder, err := strictDecode(msgSignedOrderV2, broadcast.bytesAt(1))
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}
	orderBytes := signedOrder.bytesAt(1)
	order, err := strictDecode(msgTaskOrderV2, orderBytes)
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}

	sessionID, err := order.hash32At(msgTaskOrderV2, 4)
	if err != nil {
		return BusActionScopeV2{}, nil, err
	}
	orderSequence := order.uint64At(5)
	modelID := order.stringAt(6)
	userAddress := order.stringAt(3)
	if modelID == "" || userAddress == "" {
		return BusActionScopeV2{}, nil, fmt.Errorf("%w: %s requires model_id and user_address", ErrDecode, msgTaskOrderV2)
	}

	// task_id = H_FIELDS_V1("TRUEOPEN_TASK_ID_V1", session_id, u64be(order_sequence)),
	// the registered two-field domain. task_hash is not derived here; see
	// DecodedEnvelope.OrderBytes.
	taskID := sha256.Sum256(frame(append([][]byte{[]byte(domainTaskIDV1)}, sessionID, u64be(orderSequence))...))
	scope.TaskID = taskID[:]
	scope.ExpectedSubject = subjectTaskOpenPrefix + modelID
	scope.ModelID = &modelID
	scope.PayloadActor = &userAddress
	return scope, orderBytes, nil
}
