package bus

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The golden vector covers OPEN_VERIFY only, so seven of the eight scope
// projections would otherwise be
// unexercised - and a wrong field number there attributes an action to the wrong
// participant, or looks up the wrong Task, rather than failing. These tests build
// a minimal payload for each kind and assert the whole projection.

func varintField(number uint32, value uint64) []byte {
	out := appendVarint(nil, uint64(number)<<3|wireVarint)
	return appendVarint(out, value)
}

func stringField(number uint32, value string) []byte {
	return encodeBytesField(number, []byte(value))
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func hash(fill byte) []byte { return bytes.Repeat([]byte{fill}, 32) }

const (
	scopeTaskIDFill   = 0xa1
	scopeTaskHashFill = 0xa2
	scopeActor        = "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut"
	scopeUser         = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
)

func taskIDHex() string { return hex.EncodeToString(hash(scopeTaskIDFill)) }

// candidateMemberRef builds a CandidateMemberRefV1 with every field populated,
// so the projection has to reach operator_address by number rather than by being
// the only string present.
func candidateMemberRef(operator string) []byte {
	return join(
		encodeBytesField(1, hash(0xb1)),
		varintField(2, 7),
		varintField(3, 3),
		stringField(4, operator),
	)
}

func TestScopeProjectionCoversEveryKind(t *testing.T) {
	taskID, taskHash := hash(scopeTaskIDFill), hash(scopeTaskHashFill)

	for _, testCase := range []struct {
		name        string
		kind        int32
		payloadType int32
		payload     []byte
		subject     string
		wantHash    bool
		wantModel   string
		// wantRound is -1 when the projection must leave verify_round absent.
		wantRound int64
		wantActor string
	}{
		{
			name: "WORKER_HANDRAISE", kind: KindWorkerHandraise, payloadType: PayloadTypeWorkerHandraiseV1,
			payload: join(
				varintField(1, 1), stringField(2, "c"),
				encodeBytesField(3, taskID), encodeBytesField(4, taskHash),
				stringField(5, "model-a"), varintField(6, 2),
				encodeBytesField(7, candidateMemberRef(scopeActor)),
			),
			subject:  subjectWorkerHandraisePrefix + taskIDHex(),
			wantHash: true, wantModel: "model-a", wantRound: -1, wantActor: scopeActor,
		},
		{
			name: "WORKER_ASSIGNMENT_NOTIFY", kind: KindWorkerAssignmentNotify, payloadType: PayloadTypeWorkerAssignmentNotifyV1,
			payload: join(
				encodeBytesField(1, taskID), encodeBytesField(2, taskHash),
				stringField(3, scopeActor), varintField(4, 100),
			),
			subject:  subjectWorkerAssignmentPrefix + taskIDHex(),
			wantHash: true, wantRound: -1, wantActor: scopeActor,
		},
		{
			name: "OUTPUT_AVAILABLE", kind: KindOutputAvailable, payloadType: PayloadTypeOutputAvailableV1,
			payload: join(
				encodeBytesField(1, taskID), encodeBytesField(2, taskHash),
				encodeBytesField(3, hash(0xc1)), stringField(4, scopeActor),
			),
			subject:  subjectOutputAvailablePrefix + taskIDHex(),
			wantHash: true, wantRound: -1, wantActor: scopeActor,
		},
		{
			name: "OPEN_VERIFY", kind: KindOpenVerify, payloadType: PayloadTypeOpenVerifyV1,
			payload: join(
				encodeBytesField(1, taskID), encodeBytesField(2, taskHash),
				stringField(3, "model-b"), varintField(4, 1),
				encodeBytesField(5, hash(0xc2)), encodeBytesField(6, hash(0xc3)),
				stringField(7, scopeActor), varintField(8, 4),
			),
			subject:  subjectOpenVerifyPrefix + taskIDHex(),
			wantHash: true, wantModel: "model-b", wantRound: 4, wantActor: scopeActor,
		},
		{
			// task_hash is loaded from Task authority for this kind, so the
			// projection must leave it absent rather than invent one.
			name: "VERIFIER_HANDRAISE", kind: KindVerifierHandraise, payloadType: PayloadTypeVerifierHandraiseV1,
			payload: join(
				varintField(1, 1), stringField(2, "c"),
				encodeBytesField(3, taskID), varintField(4, 5),
				encodeBytesField(5, hash(0xc4)), encodeBytesField(6, hash(0xc5)),
				stringField(7, "model-c"), varintField(8, 2),
				encodeBytesField(9, candidateMemberRef(scopeActor)),
			),
			subject:  subjectVerifierHandraisePrefix + taskIDHex(),
			wantHash: false, wantModel: "model-c", wantRound: 5, wantActor: scopeActor,
		},
		{
			// The payload names a selected set, so there is no single actor.
			name: "VERIFIER_ASSIGNMENT_NOTIFY", kind: KindVerifierAssignmentNotify, payloadType: PayloadTypeVerifierAssignmentNotifyV1,
			payload: join(
				encodeBytesField(1, taskID), encodeBytesField(2, taskHash),
				varintField(3, 6), encodeBytesField(5, hash(0xc6)),
			),
			subject:  subjectVerifierAssignmentPrefix + taskIDHex(),
			wantHash: true, wantRound: 6, wantActor: "",
		},
		{
			// task_hash and model_id both come from Task authority here.
			name: "VERIFY_RESULT", kind: KindVerifyResult, payloadType: PayloadTypeVerifyResultV1,
			payload: join(
				varintField(1, 2), stringField(2, "c"),
				encodeBytesField(3, taskID), varintField(4, 7),
				stringField(5, scopeActor), varintField(6, 1),
			),
			subject:  subjectVerifyResultPrefix + taskIDHex(),
			wantHash: false, wantRound: 7, wantActor: scopeActor,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			scope, orderBytes, err := projectScope(testCase.kind, testCase.payloadType, testCase.payload)
			if err != nil {
				t.Fatalf("project: %v", err)
			}
			if orderBytes != nil {
				t.Fatalf("OrderBytes is only set for ORDER_BROADCAST, got %d bytes", len(orderBytes))
			}
			if !bytes.Equal(scope.TaskID, taskID) {
				t.Fatalf("task_id %x, want %x", scope.TaskID, taskID)
			}
			if scope.ExpectedSubject != testCase.subject {
				t.Fatalf("subject %q, want %q", scope.ExpectedSubject, testCase.subject)
			}
			if testCase.wantHash {
				if !bytes.Equal(scope.TaskHash, taskHash) {
					t.Fatalf("task_hash %x, want %x", scope.TaskHash, taskHash)
				}
			} else if scope.TaskHash != nil {
				t.Fatalf("task_hash must be absent for %s, got %x", testCase.name, scope.TaskHash)
			}
			if testCase.wantModel == "" {
				if scope.ModelID != nil {
					t.Fatalf("model_id must be absent, got %q", *scope.ModelID)
				}
			} else if scope.ModelID == nil || *scope.ModelID != testCase.wantModel {
				t.Fatalf("model_id %v, want %q", scope.ModelID, testCase.wantModel)
			}
			if testCase.wantRound < 0 {
				if scope.VerifyRound != nil {
					t.Fatalf("verify_round must be absent, got %d", *scope.VerifyRound)
				}
			} else if scope.VerifyRound == nil || int64(*scope.VerifyRound) != testCase.wantRound {
				t.Fatalf("verify_round %v, want %d", scope.VerifyRound, testCase.wantRound)
			}
			if testCase.wantActor == "" {
				if scope.PayloadActor != nil {
					t.Fatalf("payload_actor must be absent, got %q", *scope.PayloadActor)
				}
			} else if scope.PayloadActor == nil || *scope.PayloadActor != testCase.wantActor {
				t.Fatalf("payload_actor %v, want %q", scope.PayloadActor, testCase.wantActor)
			}
		})
	}
}

func TestScopeProjectionRejectsZeroVerifyRound(t *testing.T) {
	taskID, taskHash := hash(scopeTaskIDFill), hash(scopeTaskHashFill)
	for _, testCase := range []struct {
		name       string
		roundField []byte
	}{
		{name: "missing"},
		{name: "explicit zero", roundField: varintField(8, 0)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			payload := join(
				encodeBytesField(1, taskID), encodeBytesField(2, taskHash),
				stringField(3, "model-b"), varintField(4, 1),
				encodeBytesField(5, hash(0xc2)), encodeBytesField(6, hash(0xc3)),
				stringField(7, scopeActor), testCase.roundField,
			)

			_, _, err := projectScope(KindOpenVerify, PayloadTypeOpenVerifyV1, payload)
			if !errors.Is(err, ErrDecode) || !strings.Contains(err.Error(), "verify_round must be greater than 0") {
				t.Fatalf("zero/missing verify_round error = %v", err)
			}
		})
	}
}

// TestOrderBroadcastScope covers the one kind whose task_id is derived rather
// than carried: §5.5 recomputes it from signed_order.order per TaskOrder §3.
func TestOrderBroadcastScope(t *testing.T) {
	sessionID := hash(0xd1)
	const orderSequence = 42
	order := join(
		varintField(1, 2), stringField(2, "c"), stringField(3, scopeUser),
		encodeBytesField(4, sessionID), varintField(5, orderSequence),
		stringField(6, "model-x"), varintField(7, 3),
	)
	payload := encodeBytesField(1, encodeBytesField(1, order))

	scope, orderBytes, err := projectScope(KindOrderBroadcast, PayloadTypeOrderBroadcastV1, payload)
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	// task_id = H_FIELDS_V1("TRUEOPEN_TASK_ID_V1", session_id, u64be(order_sequence)),
	// recomputed here rather than read back from the projection.
	want := sha256Sum(frame([]byte(domainTaskIDV1), sessionID, u64be(orderSequence)))
	if !bytes.Equal(scope.TaskID, want[:]) {
		t.Fatalf("derived task_id %x, want %x", scope.TaskID, want)
	}
	if scope.ExpectedSubject != subjectTaskOpenPrefix+"model-x" {
		t.Fatalf("subject %q", scope.ExpectedSubject)
	}
	if scope.ModelID == nil || *scope.ModelID != "model-x" {
		t.Fatalf("model_id %v", scope.ModelID)
	}
	if scope.PayloadActor == nil || *scope.PayloadActor != scopeUser {
		t.Fatalf("payload_actor %v", scope.PayloadActor)
	}
	// task_hash is deliberately absent: the caller recomputes it from OrderBytes
	// with its own registered TRUEOPEN_TASK_ORDER_V2 implementation.
	if scope.TaskHash != nil {
		t.Fatalf("task_hash must be absent for ORDER_BROADCAST, got %x", scope.TaskHash)
	}
	if !bytes.Equal(orderBytes, order) {
		t.Fatal("OrderBytes is not the exact serialized TaskOrderV2")
	}
}

// TestScopeRejectsMissingRequiredFields confirms the projection fails loudly
// rather than producing a scope with a zero task_id or an empty actor, either of
// which would compare equal to nothing and be attributed to no one.
func TestScopeRejectsMissingRequiredFields(t *testing.T) {
	taskID, taskHash := hash(scopeTaskIDFill), hash(scopeTaskHashFill)
	for _, testCase := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{"no task_id", join(encodeBytesField(2, taskHash), stringField(3, scopeActor)), "want raw32"},
		{"short task_id", join(encodeBytesField(1, []byte{1, 2}), encodeBytesField(2, taskHash), stringField(3, scopeActor)), "want raw32"},
		{"no task_hash", join(encodeBytesField(1, taskID), stringField(3, scopeActor)), "want raw32"},
		{"empty actor", join(encodeBytesField(1, taskID), encodeBytesField(2, taskHash)), "operator address is empty"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, _, err := projectScope(KindWorkerAssignmentNotify, PayloadTypeWorkerAssignmentNotifyV1, testCase.payload)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

// TestProjectActorRejectsAmbiguousTable pins the guard on a scope table naming
// both a direct actor field and a member ref. No kind does, and the point is
// that adding one would fail rather than silently pick a winner.
func TestProjectActorRejectsAmbiguousTable(t *testing.T) {
	payload, err := strictDecode(msgWorkerAssignmentNotifyV1, join(
		encodeBytesField(1, hash(scopeTaskIDFill)),
		encodeBytesField(2, hash(scopeTaskHashFill)),
		stringField(3, scopeActor)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projectActor(payload, msgWorkerAssignmentNotifyV1, scopePaths{actor: 3, memberRef: 7}); err == nil {
		t.Fatal("a table naming both an actor field and a member ref was accepted")
	}
}
