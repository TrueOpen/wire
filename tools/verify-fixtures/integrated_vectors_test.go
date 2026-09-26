package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func loadIntegratedFixture(t *testing.T, category, name string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "v1", category, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublishedVectors(path, category+"/"+name); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func integratedVector(t *testing.T, doc map[string]any, domain string) map[string]any {
	t.Helper()
	for _, raw := range doc["vectors"].([]any) {
		vector := raw.(map[string]any)
		if vector["domain"] == domain {
			return vector
		}
	}
	t.Fatalf("missing vector for %s", domain)
	return nil
}

func integratedField(t *testing.T, vector map[string]any, name string) map[string]any {
	t.Helper()
	for _, raw := range vector["fields"].([]any) {
		field := raw.(map[string]any)
		if field["name"] == name {
			return field
		}
	}
	t.Fatalf("missing field %s in %s", name, vector["domain"])
	return nil
}

func TestIntegratedContractVectors(t *testing.T) {
	taskFiles := []string{
		"worker_token_commitment_v1.json",
		"worker_value_commitment_v3.json",
		"worker_value_leaf_v1.json",
		"verifier_value_leaf_v1.json",
		"infer_receipt_v3.json",
		"metric_leaf_v3.json",
		"result_metric_v3.json",
		"result_receipt_v3.json",
		"task_order_v3.json",
		"output_stream_header_v1.json",
		"task_data_auth_v1.json",
		"builder_confirmation_v1.json",
		"canonical_json_v1.json",
	}
	docs := map[string]map[string]any{}
	for _, name := range taskFiles {
		docs[name] = loadIntegratedFixture(t, "task", name)
	}
	for _, name := range []string{"model_id_v1.json", "model_manifest_v4.json", "hub_domains_v1.json"} {
		loadIntegratedFixture(t, "hub", name)
	}

	token := integratedVector(t, docs["worker_token_commitment_v1.json"], "TRUEOPEN_WORKER_TOKEN_COMMITMENT_V1")
	value := integratedVector(t, docs["worker_value_commitment_v3.json"], "TRUEOPEN_WORKER_VALUE_COMMITMENT_V3")
	workerVectors := docs["worker_value_leaf_v1.json"]["vectors"].([]any)
	workerRoot := workerVectors[len(workerVectors)-1].(map[string]any)
	if integratedField(t, value, "worker_value_root")["hex"] != workerRoot["root_hex"] ||
		integratedField(t, value, "worker_values_encoded_size_bytes")["value"] != workerRoot["worker_values_encoded_size_bytes"] {
		t.Fatal("B-level commitment does not bind its published Worker value artifact")
	}
	receiptDoc := docs["infer_receipt_v3.json"]
	items := receiptDoc["commitment_list"].(map[string]any)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("infer receipt has %d evidence kinds, want 2", len(items))
	}
	if items[0].(map[string]any)["evidence_hash_or_root_hex"] != value["digest_hex"] ||
		items[1].(map[string]any)["evidence_hash_or_root_hex"] != token["digest_hex"] {
		t.Fatal("InferReceiptV3 commitment list does not bind the B and A vectors")
	}
	receipt := integratedVector(t, receiptDoc, "TRUEOPEN_INFER_RECEIPT_V3")
	evidenceHash := receiptDoc["commitment_list"].(map[string]any)["digest_hex"]
	if integratedField(t, receipt, "evidence_commitments_hash")["hex"] != evidenceHash {
		t.Fatal("InferReceiptV3 does not bind its ordered evidence list")
	}
	verifierDoc := docs["verifier_value_leaf_v1.json"]
	verifierVectors := verifierDoc["vectors"].([]any)
	verifierRoot := verifierVectors[len(verifierVectors)-1].(map[string]any)["root_hex"]
	resultMetric := docs["result_metric_v3.json"]["vectors"].([]any)
	metricRoot := resultMetric[len(resultMetric)-1].(map[string]any)["root_hex"]
	result := integratedVector(t, docs["result_receipt_v3.json"], "TRUEOPEN_RESULT_V3")
	if integratedField(t, result, "verifier_value_root")["hex"] != verifierRoot ||
		integratedField(t, result, "metric_root")["hex"] != metricRoot {
		t.Fatal("ResultReceiptV3 does not bind the published value and metric roots")
	}
	commitment := integratedVector(t, docs["result_receipt_v3.json"], "TRUEOPEN_RESULT_COMMITMENT_V3")
	if integratedField(t, commitment, "verifier_value_root")["hex"] != verifierRoot {
		t.Fatal("result commitment does not bind the Verifier value root")
	}
	payload := integratedVector(t, docs["result_receipt_v3.json"], "TRUEOPEN_VERIFIER_RESULT_PAYLOAD_V2")
	payloadBytes, err := hex.DecodeString(payload["payload_hex"].(string))
	if err != nil {
		t.Fatal(err)
	}
	parts := splitCanonicalFrame(t, payloadBytes)
	if len(parts) != 18 {
		t.Fatalf("V2 reveal payload has %d parts, want 18", len(parts))
	}
	if len(parts[12]) != 4 || string(parts[0]) != "VERIFIER_RESULT_REVEAL_V2" ||
		hex.EncodeToString(parts[7]) != receipt["digest_hex"] ||
		hex.EncodeToString(parts[10]) != verifierRoot ||
		hex.EncodeToString(parts[11]) != metricRoot ||
		binary.BigEndian.Uint32(parts[12]) != 3 ||
		!bytes.Equal(parts[17], make([]byte, 32)) {
		t.Fatal("V2 reveal payload is not linked to the V3 receipt and evidence roots")
	}
	// The receipt and the reveal both name the Verifier's evidence manifest by
	// bundle hash and size. They must name the manifest this release publishes,
	// so a manifest change cannot leave them pointing at a retired one.
	var manifest map[string]any
	for _, raw := range docs["canonical_json_v1.json"]["vectors"].([]any) {
		if vector := raw.(map[string]any); vector["name"] == "evidence_bundle_manifest_v1" {
			manifest = vector
		}
	}
	if manifest == nil {
		t.Fatal("canonical_json_v1.json publishes no Verifier evidence manifest")
	}
	manifestSize, err := strconv.ParseUint(fmt.Sprint(manifest["payload_bytes"]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if integratedField(t, result, "verifier_evidence_bundle_hash")["hex"] != manifest["digest_hex"] ||
		fmt.Sprint(integratedField(t, result, "verifier_evidence_manifest_size_bytes")["value"]) != fmt.Sprint(manifestSize) ||
		hex.EncodeToString(parts[15]) != manifest["digest_hex"] ||
		len(parts[16]) != 8 || binary.BigEndian.Uint64(parts[16]) != manifestSize {
		t.Fatal("ResultReceiptV3 and the V2 reveal do not name the published Verifier evidence manifest")
	}
	for _, raw := range docs["task_order_v3.json"]["vectors"].([]any) {
		order := raw.(map[string]any)
		if order["domain"] != "TRUEOPEN_TASK_ORDER_V3" {
			continue
		}
		fields := order["fields"].([]any)
		if len(fields) != 28 {
			t.Fatalf("TaskOrderV3 has %d fields", len(fields))
		}
		if integratedField(t, order, "model_id")["type"] != "bytes" {
			t.Fatal("TaskOrderV3 model_id is not raw Hash32")
		}
	}
}

func splitCanonicalFrame(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var parts [][]byte
	for len(raw) > 0 {
		if len(raw) < 8 {
			t.Fatal("short canonical frame length")
		}
		size := binary.BigEndian.Uint64(raw[:8])
		raw = raw[8:]
		if size > uint64(len(raw)) {
			t.Fatal("canonical frame length exceeds remaining bytes")
		}
		parts = append(parts, raw[:size])
		raw = raw[size:]
	}
	return parts
}

func TestModelProjectionV3DigestChain(t *testing.T) {
	identity := loadIntegratedFixture(t, "hub", "model_id_v1.json")
	modelID := integratedVector(t, identity, "TRUEOPEN_MODEL_ID_V1")["digest_hex"].(string)
	profile := loadIntegratedFixture(t, "hub", "model_profile_canonical_v3.json")
	projection := profile["canonical_projection"].(map[string]any)
	if projection["model_id"] != "0x"+modelID {
		t.Fatal("model projection does not use the derived model ID")
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	declaredSize, err := profile["canonical_projection_bytes"].(json.Number).Int64()
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(encoded)) != declaredSize {
		t.Fatal("canonical model projection length mismatch")
	}
	projectionDigest := sha256.Sum256(encodeHV1("TRUEOPEN_MODEL_CHAIN_PROJECTION_V3", encoded))
	if hex.EncodeToString(projectionDigest[:]) != profile["chain_projection_hash"] {
		t.Fatal("model chain projection digest mismatch")
	}
	registration := []byte(profile["registration_payload_bytes"].(string))
	registrationDigest := sha256.Sum256(encodeHV1("TRUEOPEN_MODEL_REGISTRATION_DIGEST_V3", registration))
	if hex.EncodeToString(registrationDigest[:]) != profile["registration_digest"] {
		t.Fatal("model registration digest mismatch")
	}
	manifest := loadIntegratedFixture(t, "hub", "model_manifest_v4.json")
	manifestBytes, err := json.Marshal(manifest["manifest"])
	if err != nil {
		t.Fatal(err)
	}
	vector := integratedVector(t, manifest, "TRUEOPEN_MODEL_MANIFEST_V4")
	if string(manifestBytes) != vector["payload_utf8"] {
		t.Fatal("manifest vector is not canonical JSON of the published V4 object")
	}
	account := loadIntegratedFixture(t, "shared", "account_signing_v1.json")
	order := account["task_order"].(map[string]any)
	if order["domain"].(map[string]any)["version"] != "3" ||
		!strings.Contains(order["encode_type"].(string), "bytes32 modelId") {
		t.Fatal("Task Order EIP-712 vector does not use version 3 and bytes32 modelId")
	}
}

// TestModelIDSeparatesOwnerCaseAndChain pins the identity boundary rather than
// one digest: the same repository under another registrant, in another case,
// or on another chain must be a different model. Each case changes exactly one
// input of P1, so a digest that still matched P1 would mean that input had
// dropped out of the preimage.
func TestModelIDSeparatesOwnerCaseAndChain(t *testing.T) {
	doc := loadIntegratedFixture(t, "hub", "model_id_v1.json")
	named := map[string]map[string]any{}
	for _, raw := range doc["vectors"].([]any) {
		vector := raw.(map[string]any)
		named[vector["name"].(string)] = vector
	}
	reference := named["model_id_p1_reference"]
	if reference == nil {
		t.Fatal("missing model_id_p1_reference")
	}
	cases := map[string]string{
		"model_id_p2_other_owner":    "proposer_address",
		"model_id_p3_case_preserved": "repo_id",
		"model_id_p4_other_chain":    "chain_id",
	}
	digests := map[string]string{reference["digest_hex"].(string): "model_id_p1_reference"}
	for name, changed := range cases {
		vector := named[name]
		if vector == nil {
			t.Fatalf("missing %s", name)
		}
		for _, field := range []string{"chain_id", "provider", "repo_id", "proposer_address"} {
			same := modelIDFieldValue(t, reference, field) == modelIDFieldValue(t, vector, field)
			if field == changed && same {
				t.Fatalf("%s must change %s", name, field)
			}
			if field != changed && !same {
				t.Fatalf("%s changes %s as well as %s", name, field, changed)
			}
		}
		digest := vector["digest_hex"].(string)
		if previous, seen := digests[digest]; seen {
			t.Fatalf("%s derives the same model_id as %s", name, previous)
		}
		digests[digest] = name
	}

	negative, ok := doc["negative"].([]any)
	if !ok || len(negative) == 0 {
		t.Fatal("model_id_v1.json publishes no negative cases")
	}
	for _, raw := range negative {
		row := raw.(map[string]any)
		input, _ := row["input"].(map[string]any)
		expect, _ := row["expect"].(string)
		if row["name"] == "" || row["reason"] == "" || len(input) != 1 || !strings.HasPrefix(expect, "reject_") {
			t.Fatalf("negative case %v must name one input, a reject_* expectation and a reason", row["name"])
		}
	}
}

func modelIDFieldValue(t *testing.T, vector map[string]any, name string) string {
	t.Helper()
	field := integratedField(t, vector, name)
	if value, ok := field["utf8"].(string); ok {
		return value
	}
	return field["hex"].(string)
}

// TestBuilderConfirmationCoversEveryObject pins which object each storage
// confirmation names. A Worker writes two evidence bundles per round, so its
// A-level and B-level manifests are two objects with two confirmations; a
// single Worker case could only ever confirm one of them. Evidence manifests
// carry their typed evidence_kind and INPUT/OUTPUT carry UNSPECIFIED, which is
// what keeps an evidence confirmation from being replayed for a data object.
func TestBuilderConfirmationCoversEveryObject(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "builder_confirmation_v1.json")
	want := map[string]string{
		"builder_confirmation_output":                "EVIDENCE_KIND_UNSPECIFIED",
		"builder_confirmation_input":                 "EVIDENCE_KIND_UNSPECIFIED",
		"builder_confirmation_verifier_evidence":     "EVIDENCE_KIND_VERIFIER_VALUE_OPENING",
		"builder_confirmation_worker_token_evidence": "EVIDENCE_KIND_WORKER_TOKEN_OPENING",
		"builder_confirmation_worker_value_evidence": "EVIDENCE_KIND_WORKER_VALUE_OPENING",
	}
	seen := map[string]bool{}
	contents := map[string]string{}
	for _, raw := range doc["vectors"].([]any) {
		vector := raw.(map[string]any)
		name := vector["name"].(string)
		kind, ok := want[name]
		if !ok {
			t.Fatalf("unexpected confirmation case %s", name)
		}
		ref := integratedField(t, vector, "object_ref")
		var objectKind, evidenceKind, content string
		for _, rawField := range ref["fields"].([]any) {
			field := rawField.(map[string]any)
			switch field["name"] {
			case "object_kind":
				objectKind, _ = field["enum"].(string)
			case "evidence_kind":
				evidenceKind, _ = field["enum"].(string)
			case "content_hash":
				content, _ = field["hex"].(string)
			}
		}
		if evidenceKind != kind {
			t.Fatalf("%s confirms evidence_kind %s, want %s", name, evidenceKind, kind)
		}
		isEvidence := objectKind == "TASK_DATA_OBJECT_KIND_EVIDENCE_MANIFEST"
		if isEvidence == (kind == "EVIDENCE_KIND_UNSPECIFIED") {
			t.Fatalf("%s pairs object kind %s with evidence_kind %s", name, objectKind, kind)
		}
		if other, dup := contents[content]; dup {
			t.Fatalf("%s and %s confirm the same object", name, other)
		}
		contents[content] = name
		seen[name] = true
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("missing confirmation case %s", name)
		}
	}
}

// TestEvidenceManifestsBindTheirArtifacts ties each published evidence bundle
// manifest to the artifacts and commitments it describes. Every manifest names
// its evidence_kind. The Worker A-level manifest lists the token-id artifacts
// whose raw bytes token_ids_v1.json publishes, and their sizes add up to the
// A-level commitment. The Worker B-level manifest lists worker_values, whose
// raw bytes are rebuilt here from the leaf preimages and must match the B-level
// commitment's size. payload_bytes is checked against the payload itself,
// because a stale declared length is how a renamed field goes unnoticed.
func TestEvidenceManifestsBindTheirArtifacts(t *testing.T) {
	manifests := map[string]map[string]any{}
	for _, raw := range loadIntegratedFixture(t, "task", "canonical_json_v1.json")["vectors"].([]any) {
		vector := raw.(map[string]any)
		name := vector["name"].(string)
		if !strings.HasPrefix(name, "evidence_bundle_manifest") {
			continue
		}
		payload := vector["payload_utf8"].(string)
		declared, err := vector["payload_bytes"].(json.Number).Int64()
		if err != nil || declared != int64(len(payload)) {
			t.Fatalf("%s declares %v payload bytes, carries %d", name, vector["payload_bytes"], len(payload))
		}
		var manifest map[string]any
		if err := json.Unmarshal([]byte(payload), &manifest); err != nil {
			t.Fatal(err)
		}
		manifests[name] = manifest
	}
	kinds := map[string]string{
		"evidence_bundle_manifest_v1":              "VERIFIER_VALUE_OPENING",
		"evidence_bundle_manifest_worker_token_v1": "WORKER_TOKEN_OPENING",
		"evidence_bundle_manifest_worker_value_v1": "WORKER_VALUE_OPENING",
	}
	for name, kind := range kinds {
		if manifests[name] == nil || manifests[name]["evidence_kind"] != kind {
			t.Fatalf("%s must carry evidence_kind %s", name, kind)
		}
	}

	artifact := func(manifest map[string]any, id string) (string, uint64) {
		for _, raw := range manifest["artifacts"].([]any) {
			item := raw.(map[string]any)
			if item["artifact_id"] == id {
				var size uint64
				if _, err := fmt.Sscan(item["size_bytes"].(string), &size); err != nil {
					t.Fatal(err)
				}
				return item["content_hash"].(string), size
			}
		}
		t.Fatalf("manifest has no %s artifact", id)
		return "", 0
	}
	sum := func(raw []byte) string {
		digest := sha256.Sum256(raw)
		return hex.EncodeToString(digest[:])
	}

	commitments := map[string]uint64{}
	for _, raw := range loadIntegratedFixture(t, "task", "infer_receipt_v3.json")["commitment_list"].(map[string]any)["items"].([]any) {
		item := raw.(map[string]any)
		size, err := item["encoded_size_bytes"].(json.Number).Int64()
		if err != nil {
			t.Fatal(err)
		}
		commitments[item["evidence_kind_name"].(string)] = uint64(size)
	}

	tokenA := manifests["evidence_bundle_manifest_worker_token_v1"]
	var tokenBytes uint64
	for _, raw := range loadIntegratedFixture(t, "task", "token_ids_v1.json")["vectors"].([]any) {
		vector := raw.(map[string]any)
		id := strings.TrimSuffix(vector["name"].(string), "_v1")
		want, err := hex.DecodeString(vector["token_ids_raw_hex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		hash, size := artifact(tokenA, id)
		if hash != sum(want) || size != uint64(len(want)) {
			t.Fatalf("A-level manifest %s does not match the published token ids", id)
		}
		tokenBytes += size
	}
	if tokenBytes != commitments["EVIDENCE_KIND_WORKER_TOKEN_OPENING"] {
		t.Fatalf("A-level artifacts total %d bytes, commitment says %d", tokenBytes, commitments["EVIDENCE_KIND_WORKER_TOKEN_OPENING"])
	}

	var leaves [][]byte
	for _, raw := range loadIntegratedFixture(t, "task", "worker_value_leaf_v1.json")["vectors"].([]any) {
		vector := raw.(map[string]any)
		if vector["name"] != "worker_value_leaf" {
			continue
		}
		preimage, err := hex.DecodeString(vector["preimage_hex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		parts := splitCanonicalFrame(t, preimage)
		if len(parts) != 3 {
			t.Fatalf("worker value leaf preimage has %d frames, want domain, version and leaf bytes", len(parts))
		}
		leaves = append(leaves, parts[2])
	}
	values := binary.BigEndian.AppendUint32(nil, uint32(len(leaves)))
	for _, leaf := range leaves {
		values = append(values, leaf...)
	}
	hash, size := artifact(manifests["evidence_bundle_manifest_worker_value_v1"], "worker_values")
	if hash != sum(values) || size != uint64(len(values)) || size != commitments["EVIDENCE_KIND_WORKER_VALUE_OPENING"] {
		t.Fatalf("B-level manifest does not describe the worker_values the B-level commitment sizes")
	}
}

// fieldInt reads an integer field value, which the fixtures decode as
// json.Number through loadIntegratedFixture.
func fieldInt(t *testing.T, field map[string]any) int64 {
	t.Helper()
	value, err := strconv.ParseInt(fmt.Sprint(field["value"]), 10, 64)
	if err != nil {
		t.Fatalf("field %s: %v", field["name"], err)
	}
	return value
}

// Two same-typed receipt fields that carry equal values cannot pin their
// order: swapping them leaves the digest unchanged. The distinct-count vector
// must differ from the base only in generated_token_count, and must give it a
// value output_leaf_count does not have.
func TestInferReceiptCountsHaveDistinctValues(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "infer_receipt_v3.json")
	vectors := map[string]map[string]any{}
	for _, raw := range doc["vectors"].([]any) {
		vector := raw.(map[string]any)
		vectors[fmt.Sprint(vector["name"])] = vector
	}
	base, distinct := vectors["infer_receipt_v3"], vectors["infer_receipt_v3_distinct_counts"]
	if base == nil || distinct == nil {
		t.Fatal("infer_receipt_v3.json must publish the base and the distinct-count vectors")
	}
	if fieldInt(t, integratedField(t, distinct, "generated_token_count")) ==
		fieldInt(t, integratedField(t, distinct, "output_leaf_count")) {
		t.Fatal("the distinct-count vector gives both counts the same value")
	}
	baseFields, distinctFields := base["fields"].([]any), distinct["fields"].([]any)
	if len(baseFields) != len(distinctFields) {
		t.Fatal("the two receipt vectors have different field lists")
	}
	for i := range baseFields {
		a, b := baseFields[i].(map[string]any), distinctFields[i].(map[string]any)
		if a["name"] != b["name"] {
			t.Fatalf("field %d is %v in one vector and %v in the other", i, a["name"], b["name"])
		}
		if fmt.Sprint(a) != fmt.Sprint(b) && a["name"] != "generated_token_count" {
			t.Fatalf("the vectors also differ in %v", a["name"])
		}
	}
	if base["digest_hex"] == distinct["digest_hex"] {
		t.Fatal("changing generated_token_count did not change the receipt digest")
	}
}

// Every finite metric leaf must satisfy rank_delta = effective_rank(verifier)
// - effective_rank(worker), with effective_rank(0) = required_top_k + 1, and at
// least one leaf must exercise a zero rank so the rule is pinned at all.
func TestMetricLeafRankDeltaUsesEffectiveRank(t *testing.T) {
	var zeroRankSeen bool
	for _, name := range []string{"metric_leaf_v3.json", "result_metric_v3.json"} {
		for _, raw := range loadIntegratedFixture(t, "task", name)["vectors"].([]any) {
			vector := raw.(map[string]any)
			if vector["domain"] != "TRUEOPEN_PREFILL_TOKEN_METRIC_LEAF_V3" {
				continue
			}
			leaf := map[string]any{"fields": integratedField(t, vector, "canonical_leaf_bytes")["fields"], "domain": vector["domain"]}
			if integratedField(t, leaf, "finite_flag")["value"] != true {
				continue
			}
			k := fieldInt(t, integratedField(t, leaf, "required_top_k"))
			effective := func(rank int64) int64 {
				if rank == 0 {
					zeroRankSeen = true
					return k + 1
				}
				return rank
			}
			worker := fieldInt(t, integratedField(t, leaf, "worker_rank"))
			verifier := fieldInt(t, integratedField(t, leaf, "verifier_rank"))
			if got, want := fieldInt(t, integratedField(t, leaf, "rank_delta")), effective(verifier)-effective(worker); got != want {
				t.Fatalf("%s %v: rank_delta = %d, want %d", name, vector["name"], got, want)
			}
		}
	}
	if !zeroRankSeen {
		t.Fatal("no finite metric leaf has a zero rank, so effective_rank(0) is unpinned")
	}
}
