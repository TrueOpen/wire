package bus

// This file is a pinned projection of the protobuf field tables the strict
// decoder needs: proto/bus/v1/envelope.proto, proto/bus/v1/payload.proto,
// proto/bus/v1/nats_user_binding.proto,
// the task.v1 payload messages the bus reuses verbatim, and the generated-
// code-free BuilderEvidenceV2 subtree.
//
// It is a table rather than generated code on purpose. keeper_api_contract.md §5.5
// requires a decoder with no generated Hub/Task/Bus code dependency, because a
// Task-owned evidence message that imported the Bus generated package - which in
// turn references Task payload types - would close a Task -> Bus -> Task import
// cycle in the consumer. ADR-0013 rejects embedding the generated envelope for
// exactly this reason. A hand-maintained table would drift, so
// TestPinnedTableMatchesProtoSources re-derives every entry from the .proto
// sources and fails on any difference: the table is checked against the schema,
// never trusted on its own.
//
// The tables are COMPLETE, not only the fields the scope projection reads. A
// strict decoder has to reject unknown fields, and it can only do that if it
// knows every field a message legitimately has.

// fieldKind is the protobuf wire shape a field is allowed to arrive in. Field
// numbers alone are not enough: accepting a varint where bytes are declared
// would let a crafted envelope present a different value to the same table.
type fieldKind uint8

const (
	kindVarint fieldKind = iota
	kindString
	kindBytes
	kindMessage
)

type fieldSpec struct {
	name string
	kind fieldKind
	// message is the fully-qualified type of a kindMessage field, used to select
	// the nested table so unknown-field rejection reaches the whole subtree.
	message  string
	repeated bool
}

// messageSpec maps field number to its declaration. A number absent from the map
// is an unknown field and is rejected.
type messageSpec map[uint32]fieldSpec

// Fully-qualified names of the messages the decoder resolves. They are constants
// so a typo is a compile error rather than a nil table at verification time.
const (
	msgBusEnvelopeV1                   = "bus.v1.BusEnvelopeV1"
	msgOrderBroadcastV1                = "bus.v1.OrderBroadcastV1"
	msgSignedOrderV2                   = "task.v1.SignedOrderV2"
	msgTaskOrderV2                     = "task.v1.TaskOrderV2"
	msgWorkerHandraiseV1               = "task.v1.WorkerHandraiseV1"
	msgCandidateMemberRefV1            = "task.v1.CandidateMemberRefV1"
	msgWorkerAssignmentNotifyV1        = "bus.v1.WorkerAssignmentNotifyV1"
	msgOutputAvailableV1               = "bus.v1.OutputAvailableV1"
	msgOpenVerifyV1                    = "bus.v1.OpenVerifyV1"
	msgVerifierHandraiseV1             = "task.v1.VerifierHandraiseV1"
	msgVerifierAssignmentNotifyV1      = "bus.v1.VerifierAssignmentNotifyV1"
	msgResultReceiptV2                 = "task.v1.ResultReceiptV2"
	msgDecodingParamsV1                = "task.v1.DecodingParamsV1"
	msgBuilderEvidenceV2               = "task.v1.BuilderEvidenceV2"
	msgSignedEnvelopeEquivocationV2    = "task.v1.SignedEnvelopeEquivocationV2"
	msgSignedEnvelopeProtocolFaultV2   = "task.v1.SignedEnvelopeProtocolFaultV2"
	msgDataUnavailableStateReferenceV1 = "task.v1.DataUnavailableStateReferenceV1"
	msgNatsUserBindingV1               = "bus.v1.NatsUserBindingV1"
)

// protoTables is the pinned field table for the envelope and the transitive
// closure of every bus payload type.
var protoTables = map[string]messageSpec{
	"task.v1.BuilderEvidenceV2": {
		1: {name: "schema_version", kind: kindVarint},
		2: {name: "equivocation", kind: kindMessage, message: "task.v1.SignedEnvelopeEquivocationV2"},
		3: {name: "invalid_stage_submission", kind: kindMessage, message: "task.v1.SignedEnvelopeProtocolFaultV2"},
		5: {name: "data_unavailable", kind: kindMessage, message: "task.v1.DataUnavailableStateReferenceV1"},
	},
	"task.v1.SignedEnvelopeEquivocationV2": {
		1: {name: "envelope_a", kind: kindBytes},
		2: {name: "envelope_b", kind: kindBytes},
	},
	"task.v1.SignedEnvelopeProtocolFaultV2": {
		1: {name: "envelope", kind: kindBytes},
		2: {name: "violation", kind: kindVarint},
	},
	"task.v1.DataUnavailableStateReferenceV1": {
		1: {name: "task_id", kind: kindBytes},
		2: {name: "verify_round", kind: kindVarint},
		3: {name: "builder_operator", kind: kindString},
	},
	"bus.v1.BusEnvelopeV1": {
		1:  {name: "schema_version", kind: kindVarint},
		2:  {name: "chain_id", kind: kindString},
		3:  {name: "subject", kind: kindString},
		4:  {name: "kind", kind: kindVarint},
		5:  {name: "sender_participant_type", kind: kindVarint},
		6:  {name: "sender_operator_address", kind: kindString},
		7:  {name: "service_authorization_nonce", kind: kindVarint},
		8:  {name: "message_id", kind: kindString},
		9:  {name: "nonce", kind: kindBytes},
		10: {name: "issued_at_unix_ms", kind: kindVarint},
		11: {name: "expires_at_unix_ms", kind: kindVarint},
		12: {name: "payload_type", kind: kindVarint},
		13: {name: "payload", kind: kindBytes},
		14: {name: "payload_digest", kind: kindBytes},
		15: {name: "service_signature", kind: kindBytes},
	},
	"bus.v1.NatsUserBindingV1": {
		1: {name: "schema_version", kind: kindVarint},
		2: {name: "chain_id", kind: kindString},
		3: {name: "participant_type", kind: kindVarint},
		4: {name: "operator_address", kind: kindString},
		5: {name: "service_authorization_nonce", kind: kindVarint},
		6: {name: "nats_user_pubkey", kind: kindString},
		7: {name: "issued_at_unix_ms", kind: kindVarint},
		8: {name: "service_signature", kind: kindBytes},
	},
	"bus.v1.OrderBroadcastV1": {
		1: {name: "signed_order", kind: kindMessage, message: "task.v1.SignedOrderV2"},
	},
	"task.v1.SignedOrderV2": {
		1: {name: "order", kind: kindMessage, message: "task.v1.TaskOrderV2"},
		2: {name: "signature_scheme", kind: kindString},
		3: {name: "user_signature", kind: kindBytes},
	},
	"task.v1.TaskOrderV2": {
		1:  {name: "schema_version", kind: kindVarint},
		2:  {name: "chain_id", kind: kindString},
		3:  {name: "user_address", kind: kindString},
		4:  {name: "session_id", kind: kindBytes},
		5:  {name: "order_sequence", kind: kindVarint},
		6:  {name: "model_id", kind: kindString},
		7:  {name: "profile_version", kind: kindVarint},
		8:  {name: "task_type", kind: kindVarint},
		9:  {name: "input_hash", kind: kindBytes},
		10: {name: "input_size_bytes", kind: kindVarint},
		11: {name: "input_bucket", kind: kindVarint},
		12: {name: "output_budget_bucket", kind: kindVarint},
		13: {name: "generation_params", kind: kindMessage, message: "task.v1.GenerationParamsV1"},
		14: {name: "price_bid", kind: kindMessage, message: "shared.v1.Amount"},
		15: {name: "max_fee", kind: kindMessage, message: "shared.v1.Amount"},
		16: {name: "assignment_priority_fee", kind: kindMessage, message: "shared.v1.Amount"},
		17: {name: "tx_fee_reserve", kind: kindMessage, message: "shared.v1.Amount"},
		18: {name: "earliest_submit_height", kind: kindVarint},
		19: {name: "order_expire_height", kind: kindVarint},
		20: {name: "deadline_policy", kind: kindMessage, message: "task.v1.DeadlinePolicyV1"},
		21: {name: "timeout_bucket_version", kind: kindVarint},
		22: {name: "session_anchor_height", kind: kindVarint},
		23: {name: "session_anchor_block_hash", kind: kindBytes},
		24: {name: "builder_set_id", kind: kindString},
		25: {name: "builder_set_hash", kind: kindBytes},
	},
	"task.v1.GenerationParamsV1": {
		1: {name: "generation_params_schema_version", kind: kindVarint},
		2: {name: "max_output_tokens", kind: kindVarint},
		3: {name: "max_output_duration", kind: kindVarint},
		4: {name: "decoding_params", kind: kindMessage, message: "task.v1.DecodingParamsV1"},
	},
	"task.v1.DecodingParamsV1": {
		1:  {name: "sampling_enabled", kind: kindVarint},
		2:  {name: "temperature_milli", kind: kindVarint},
		3:  {name: "top_p_ppm", kind: kindVarint},
		4:  {name: "top_k", kind: kindVarint},
		5:  {name: "seed", kind: kindVarint},
		6:  {name: "presence_penalty_milli", kind: kindVarint},
		7:  {name: "frequency_penalty_milli", kind: kindVarint},
		8:  {name: "repetition_penalty_ppm", kind: kindVarint},
		9:  {name: "stop_sequences", kind: kindString, repeated: true},
		10: {name: "stop_token_ids", kind: kindVarint, repeated: true},
	},
	"shared.v1.Amount": {
		1: {name: "atomic_units", kind: kindString},
	},
	"task.v1.DeadlinePolicyV1": {
		1: {name: "latency_class", kind: kindVarint},
	},
	"task.v1.WorkerHandraiseV1": {
		1:  {name: "schema_version", kind: kindVarint},
		2:  {name: "chain_id", kind: kindString},
		3:  {name: "task_id", kind: kindBytes},
		4:  {name: "task_hash", kind: kindBytes},
		5:  {name: "model_id", kind: kindString},
		6:  {name: "profile_version", kind: kindVarint},
		7:  {name: "member", kind: kindMessage, message: "task.v1.CandidateMemberRefV1"},
		8:  {name: "duty", kind: kindVarint},
		9:  {name: "service_authorization_nonce", kind: kindVarint},
		10: {name: "expiry_height", kind: kindVarint},
		11: {name: "service_signature", kind: kindBytes},
	},
	"task.v1.CandidateMemberRefV1": {
		1: {name: "candidate_pool_snapshot_id", kind: kindBytes},
		2: {name: "slot", kind: kindVarint},
		3: {name: "slot_version", kind: kindVarint},
		4: {name: "operator_address", kind: kindString},
	},
	"bus.v1.WorkerAssignmentNotifyV1": {
		1: {name: "task_id", kind: kindBytes},
		2: {name: "task_hash", kind: kindBytes},
		3: {name: "winner_operator_address", kind: kindString},
		4: {name: "finalized_height", kind: kindVarint},
		5: {name: "assign_seed", kind: kindBytes},
		6: {name: "input_hash", kind: kindBytes},
		7: {name: "infer_deadline_height", kind: kindVarint},
	},
	"bus.v1.OutputAvailableV1": {
		1: {name: "task_id", kind: kindBytes},
		2: {name: "task_hash", kind: kindBytes},
		3: {name: "output_hash", kind: kindBytes},
		4: {name: "worker_operator_address", kind: kindString},
		5: {name: "published_at_unix_ms", kind: kindVarint},
	},
	"bus.v1.OpenVerifyV1": {
		1: {name: "task_id", kind: kindBytes},
		2: {name: "task_hash", kind: kindBytes},
		3: {name: "model_id", kind: kindString},
		4: {name: "profile_version", kind: kindVarint},
		5: {name: "infer_receipt_hash", kind: kindBytes},
		6: {name: "output_hash", kind: kindBytes},
		7: {name: "worker_operator_address", kind: kindString},
		8: {name: "verify_round", kind: kindVarint},
	},
	"task.v1.VerifierHandraiseV1": {
		1:  {name: "schema_version", kind: kindVarint},
		2:  {name: "chain_id", kind: kindString},
		3:  {name: "task_id", kind: kindBytes},
		4:  {name: "verify_round", kind: kindVarint},
		5:  {name: "infer_receipt_hash", kind: kindBytes},
		6:  {name: "output_hash", kind: kindBytes},
		7:  {name: "model_id", kind: kindString},
		8:  {name: "profile_version", kind: kindVarint},
		9:  {name: "member", kind: kindMessage, message: "task.v1.CandidateMemberRefV1"},
		10: {name: "duty", kind: kindVarint},
		11: {name: "service_authorization_nonce", kind: kindVarint},
		12: {name: "expiry_height", kind: kindVarint},
		13: {name: "service_signature", kind: kindBytes},
	},
	"bus.v1.VerifierAssignmentNotifyV1": {
		1: {name: "task_id", kind: kindBytes},
		2: {name: "task_hash", kind: kindBytes},
		3: {name: "verify_round", kind: kindVarint},
		4: {name: "verifiers", kind: kindMessage, message: "task.v1.SelectedVerifierV1", repeated: true},
		5: {name: "output_hash", kind: kindBytes},
		6: {name: "open_verify_height", kind: kindVarint},
		7: {name: "commit_deadline_height", kind: kindVarint},
		8: {name: "reveal_deadline_height", kind: kindVarint},
		9: {name: "verify_deadline_height", kind: kindVarint},
	},
	"task.v1.SelectedVerifierV1": {
		1: {name: "operator_address", kind: kindString},
		2: {name: "slot", kind: kindVarint},
		3: {name: "slot_version", kind: kindVarint},
	},
	"task.v1.ResultReceiptV2": {
		1:  {name: "schema_version", kind: kindVarint},
		2:  {name: "chain_id", kind: kindString},
		3:  {name: "task_id", kind: kindBytes},
		4:  {name: "verify_round", kind: kindVarint},
		5:  {name: "verifier_operator_address", kind: kindString},
		6:  {name: "service_authorization_nonce", kind: kindVarint},
		7:  {name: "generation_params_digest", kind: kindBytes},
		8:  {name: "metric_root", kind: kindBytes},
		9:  {name: "metric_summary", kind: kindMessage, message: "task.v1.MetricSummaryV1"},
		10: {name: "aggregate_proof_hash", kind: kindBytes},
		11: {name: "verifier_evidence_bundle_hash", kind: kindBytes},
		12: {name: "verifier_evidence_manifest_size_bytes", kind: kindVarint},
		13: {name: "salt", kind: kindBytes},
		14: {name: "expiry_height", kind: kindVarint},
		15: {name: "service_signature", kind: kindBytes},
	},
	"task.v1.MetricSummaryV1": {
		1:  {name: "finite_count", kind: kindVarint},
		2:  {name: "missing_compared_count", kind: kindVarint},
		3:  {name: "mean_abs_logprob_diff_fp_1e6", kind: kindVarint},
		4:  {name: "abs_logprob_diff_p95_fp_1e6", kind: kindVarint},
		5:  {name: "abs_logprob_diff_p99_fp_1e6", kind: kindVarint},
		6:  {name: "rank_delta_nonzero_rate_fp_1e6", kind: kindVarint},
		7:  {name: "topk_jaccard_mean_fp_1e6", kind: kindVarint},
		8:  {name: "union_js_p99_fp_1e6", kind: kindVarint},
		9:  {name: "compared_topk_count", kind: kindVarint},
		10: {name: "compared_rank_count", kind: kindVarint},
	},
}
