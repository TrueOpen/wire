package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sdkBodyDomains maps each User Ingress method to its body domain. The set is
// closed: a method outside it has no registered body.
var sdkBodyDomains = map[string]string{
	"OpenTask":         "TRUEOPEN_SDK_BODY_OPEN_TASK_V1",
	"SubscribeOutput":  "TRUEOPEN_SDK_BODY_SUBSCRIBE_OUTPUT_V1",
	"AckOutput":        "TRUEOPEN_SDK_BODY_ACK_OUTPUT_V1",
	"GetTaskEvents":    "TRUEOPEN_SDK_BODY_GET_TASK_EVENTS_V1",
	"PrepareChallenge": "TRUEOPEN_SDK_BODY_PREPARE_CHALLENGE_V1",
}

// Every body vector must frame exactly the fields its registry row lists, in
// order, with "optional x" rows framed as OPTIONAL_V1.
func TestSDKBodyVectorsFollowTheRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "registry", "v1", "domains.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Domains []struct {
			Domain string   `json:"domain"`
			Fields []string `json:"fields"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{}
	for _, row := range registry.Domains {
		rows[row.Domain] = row.Fields
	}
	doc := loadIntegratedFixture(t, "task", "sdk_request_body_v1.json")
	covered := map[string]bool{}
	for _, raw := range doc["vectors"].([]any) {
		vector := raw.(map[string]any)
		domain := vector["domain"].(string)
		want, registered := rows[domain]
		if !registered {
			t.Fatalf("%s: domain %s has no registry row", vector["name"], domain)
		}
		covered[domain] = true
		fields := vector["fields"].([]any)
		if len(fields) != len(want) {
			t.Fatalf("%s: %d fields, the registry lists %d", vector["name"], len(fields), len(want))
		}
		for index, rawField := range fields {
			field := rawField.(map[string]any)
			name, optional := strings.CutPrefix(want[index], "optional ")
			if field["name"] != name || (field["type"] == "optional") != optional {
				t.Fatalf("%s: field %d is %v %v, the registry lists %q", vector["name"], index, field["type"], field["name"], want[index])
			}
		}
	}
	for _, domain := range sdkBodyDomains {
		if !covered[domain] {
			t.Fatalf("no body vector for %s", domain)
		}
	}
}

// hFieldsDigest is SHA256 of H_FIELDS_V1(domain, parts...).
func hFieldsDigest(domain string, parts ...[]byte) string {
	var preimage []byte
	for _, part := range append([][]byte{[]byte(domain)}, parts...) {
		preimage = binary.BigEndian.AppendUint64(preimage, uint64(len(part)))
		preimage = append(preimage, part...)
	}
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:])
}

// The signed requests must carry the body digests, grant hash, order and task
// identity the other vectors publish, so that a consumer can walk from the
// body through the EIP-712 digest to the signature without a gap.
func TestSDKRequestVectorsLinkBodiesGrantAndOrder(t *testing.T) {
	account := loadIntegratedFixture(t, "shared", "account_signing_v1.json")
	bodies := loadIntegratedFixture(t, "task", "sdk_request_body_v1.json")
	taskData := loadIntegratedFixture(t, "task", "task_data_auth_v1.json")
	section := func(name string) map[string]any { return account[name].(map[string]any) }
	message := func(name string) map[string]any { return section(name)["message"].(map[string]any) }
	bodyDigest := func(doc map[string]any, name string) string {
		for _, raw := range doc["vectors"].([]any) {
			if vector := raw.(map[string]any); vector["name"] == name {
				return vector["digest_hex"].(string)
			}
		}
		t.Fatalf("no body vector %s", name)
		return ""
	}
	sourceDigest := func(name string) string {
		source := section(name)["body_digest_source"].(string)
		parts := strings.Fields(source)
		doc := bodies
		if strings.HasPrefix(source, "task/task_data_auth_v1.json") {
			doc = taskData
		}
		return bodyDigest(doc, strings.TrimSuffix(parts[2], ","))
	}

	zero := strings.Repeat("00", 32)
	grant := section("session_grant")
	grantHash := grant["hash_struct"].(string)
	user := account["account"].(map[string]any)
	sessionKey := account["session_key"].(map[string]any)
	if message("session_grant")["user"] != user["account_bech32"] || message("session_grant")["sessionKey"] != sessionKey["address_bytes"] ||
		message("session_grant")["chainId"] != message("sdk_request")["chainId"] {
		t.Fatal("the grant is not the account's grant of the session key on the request chain")
	}
	for name, want := range map[string]struct{ grantHash, signer, recovered string }{
		"sdk_request":               {zero, "account", user["address_bytes"].(string)},
		"sdk_request_session":       {grantHash, "session_key", sessionKey["address_bytes"].(string)},
		"task_data_request":         {zero, "account", user["address_bytes"].(string)},
		"task_data_request_session": {grantHash, "session_key", sessionKey["address_bytes"].(string)},
	} {
		if message(name)["bodyDigest"] != sourceDigest(name) {
			t.Fatalf("%s: bodyDigest is not the digest of %s", name, section(name)["body_digest_source"])
		}
		if message(name)["sessionGrantHash"] != want.grantHash {
			t.Fatalf("%s: sessionGrantHash is not %s", name, want.grantHash)
		}
		if section(name)["signer"] != want.signer || section(name)["recovered_address"] != want.recovered {
			t.Fatalf("%s: must be signed by %s", name, want.signer)
		}
	}
	for _, name := range []string{"sdk_request", "sdk_request_session"} {
		method := message(name)["method"].(string)
		source := section(name)["body_digest_source"].(string)
		if !strings.HasSuffix(source, sdkBodyDomains[method]) {
			t.Fatalf("%s: method %s is signed over a body of %s", name, method, source)
		}
		if message(name)["endpoint"] != "/nexus.v1.IngressAPI/"+method {
			t.Fatalf("%s: endpoint must be /nexus.v1.IngressAPI/%s", name, method)
		}
		envelope := section(name)["envelope"].(map[string]any)
		if envelope["request_domain"] != "TRUEOPEN_SDK_REQUEST_V2" || envelope["signer_address"] != user["account_bech32"] {
			t.Fatalf("%s: envelope must be TRUEOPEN_SDK_REQUEST_V2 for the granting user", name)
		}
	}
	if message("sdk_request")["method"] != "OpenTask" || message("sdk_request_session")["method"] == "OpenTask" {
		t.Fatal("the wallet vector opens the task; the session vector must not")
	}

	// The OpenTask body opens the signed order of task_order, and every request
	// names the task that order creates.
	order := message("task_order")
	var open map[string]any
	for _, raw := range bodies["vectors"].([]any) {
		if vector := raw.(map[string]any); vector["domain"] == sdkBodyDomains["OpenTask"] {
			open = vector
		}
	}
	field := func(name string) map[string]any { return integratedField(t, open, name) }
	if field("task_hash")["hex"] != order["taskHash"] || field("session_id")["hex"] != order["sessionId"] ||
		fieldUint(t, field("order_sequence")) != mustUint(t, order["orderSequence"]) ||
		field("user_address")["hex"] != user["address_bytes"] {
		t.Fatal("the OpenTask body does not open the task_order vector for its user")
	}
	transport := open["transport"].(map[string]any)
	if transport["payload_ref"] != "nexus://sha256/"+field("input_hash")["hex"].(string) {
		t.Fatal("payload_ref must be nexus://sha256/ followed by the lowercase hex input_hash")
	}
	sessionID, _ := hex.DecodeString(order["sessionId"].(string))
	taskID := hFieldsDigest("TRUEOPEN_TASK_ID_V1", sessionID, binary.BigEndian.AppendUint64(nil, mustUint(t, order["orderSequence"])))
	for _, name := range []string{"sdk_request", "sdk_request_session"} {
		if message(name)["sessionId"] != order["sessionId"] || message(name)["taskId"] != taskID {
			t.Fatalf("%s: sessionId and taskId must name the task the order creates", name)
		}
	}
	for _, raw := range bodies["vectors"].([]any) {
		vector := raw.(map[string]any)
		if vector["domain"] == sdkBodyDomains["OpenTask"] {
			continue
		}
		if integratedField(t, vector, "session_id")["hex"] != order["sessionId"] || integratedField(t, vector, "task_id")["hex"] != taskID {
			t.Fatalf("%s: session_id and task_id must name the opened task", vector["name"])
		}
	}
}

func mustUint(t *testing.T, value any) uint64 {
	t.Helper()
	return uint64(numberInt(t, json.Number(value.(string))))
}
