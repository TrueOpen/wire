package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// decodeNumbers parses JSON keeping integers exact.
func decodeNumbers(t *testing.T, raw string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var out map[string]any
	if err := decoder.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func numberInt(t *testing.T, value any) int64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("%v is not a JSON number", value)
	}
	parsed, err := number.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// Every range case changes one decoding parameter of the generation_params_v1
// base. An accepted case must be exactly that change in canonical form, and
// whether it is accepted must follow from the ranges the file publishes.
func TestGenerationParamRangeBoundaries(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "generation_params_ranges_v1.json")
	base := loadIntegratedFixture(t, "task", "generation_params_v1.json")
	ranges := doc["ranges"].(map[string]any)
	seen := map[string]bool{}
	for _, raw := range doc["cases"].([]any) {
		row := raw.(map[string]any)
		name := row["name"].(string)
		field := strings.TrimPrefix(row["field"].(string), "decoding_params.")
		value := numberInt(t, row["value"])
		bounds := ranges[field].(map[string]any)
		minimum := numberInt(t, bounds["min"])
		maxValue, ok := bounds["max"]
		if !ok {
			maxValue = bounds["default_max"]
		}
		maximum := numberInt(t, maxValue)
		inRange := value >= minimum && value <= maximum
		seen[field+"/"+row["boundary"].(string)] = true

		generation := row["generation_params"].(map[string]any)
		if (generation["expect"] == "accept") != inRange {
			t.Fatalf("%s: generation_params expect %v, but %d is in range: %v", name, generation["expect"], value, inRange)
		}
		// The order projection bounds every field except top_k.
		orderAccepts := inRange || field == "top_k"
		if (row["task_order_v3"].(map[string]any)["expect"] == "accept") != orderAccepts {
			t.Fatalf("%s: task_order_v3 expectation does not follow the ranges", name)
		}
		if !inRange {
			continue
		}
		payload := decodeNumbers(t, base["canonical_json"].(string))
		payload["decoding_params"].(map[string]any)[field] = json.Number(strconv.FormatInt(value, 10))
		encoded, err := canonicalJSONBytes(payload)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != generation["payload_utf8"] {
			t.Fatalf("%s: payload is not the base with only %s changed", name, field)
		}
	}
	for field := range ranges {
		for _, boundary := range []string{"min", "max", "max+1"} {
			if !seen[field+"/"+boundary] {
				t.Fatalf("no %s case for %s", boundary, field)
			}
		}
		if numberInt(t, ranges[field].(map[string]any)["min"]) > 0 && !seen[field+"/min-1"] {
			t.Fatalf("no min-1 case for %s", field)
		}
	}
}

// order_value is recomputed here with arbitrary-precision integers, apart
// from the implementation that produced the vectors.
func TestOrderEconomics(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "order_economics_v1.json")
	maxU64 := new(big.Int).SetUint64(^uint64(0))
	amount := func(text string) (*big.Int, bool) {
		if text == "" || (len(text) > 1 && text[0] == '0') || strings.Trim(text, "0123456789") != "" {
			return nil, false
		}
		value, ok := new(big.Int).SetString(text, 10)
		return value, ok && value.Cmp(maxU64) <= 0
	}
	for _, raw := range doc["cases"].([]any) {
		row := raw.(map[string]any)
		name := row["name"].(string)
		in := row["inputs"].(map[string]any)
		tokens, _ := new(big.Int).SetString(fmt.Sprint(in["max_output_tokens"]), 10)
		ratio := big.NewInt(numberInt(t, in["verify_ratio_bps"]))
		price, priceOK := amount(in["price_bid"].(string))
		maxFee, maxFeeOK := amount(in["max_fee"].(string))
		reserve, reserveOK := amount(in["tx_fee_reserve"].(string))

		accept := priceOK && price.Sign() > 0 && maxFeeOK && reserveOK
		var worker, verify, value *big.Int
		if accept {
			worker = new(big.Int).Div(new(big.Int).Mul(tokens, price), big.NewInt(1_000_000))
			verify = new(big.Int).Div(new(big.Int).Mul(worker, ratio), big.NewInt(10_000))
			value = new(big.Int).Add(worker, verify)
			reserved := new(big.Int).Add(value, reserve)
			accept = worker.Cmp(maxU64) <= 0 && verify.Cmp(maxU64) <= 0 && value.Cmp(maxU64) <= 0 &&
				value.Sign() > 0 && reserved.Cmp(maxU64) <= 0 && reserved.Cmp(maxFee) <= 0
		}
		if (row["expect"] == "accept") != accept {
			t.Fatalf("%s: published %v, recomputed accept=%v", name, row["expect"], accept)
		}
		if !accept {
			continue
		}
		for key, want := range map[string]*big.Int{"worker_max": worker, "verify_max": verify, "order_value": value} {
			if row[key] != want.String() {
				t.Fatalf("%s: %s is %v, recomputed %s", name, key, row[key], want)
			}
		}
	}
}

// Each EIP-712 case must be the order of the task_order_v3 vector it names:
// same task hash, and every message field copied from that order's fields.
func TestTaskOrderEIP712LinksTheOrderVectors(t *testing.T) {
	doc := loadIntegratedFixture(t, "task", "task_order_eip712_v1.json")
	orders := loadIntegratedFixture(t, "task", "task_order_v3.json")
	account := loadIntegratedFixture(t, "shared", "account_signing_v1.json")
	signing := account["task_order"].(map[string]any)
	if doc["domain"].(map[string]any)["domain_separator"] != signing["domain"].(map[string]any)["domain_separator"] ||
		doc["encode_type"] != signing["encode_type"] || doc["type_hash"] != signing["type_hash"] {
		t.Fatal("the EIP-712 cases do not use the published order domain and type")
	}
	named := map[string]map[string]any{}
	for _, raw := range orders["vectors"].([]any) {
		vector := raw.(map[string]any)
		named[vector["name"].(string)] = vector
	}
	cases := doc["vectors"].([]any)
	if len(cases) == 0 {
		t.Fatal("no EIP-712 cases")
	}
	for _, raw := range cases {
		row := raw.(map[string]any)
		ref := strings.TrimPrefix(row["task_order_vector"].(string), "task/task_order_v3.json#")
		order := named[ref]
		if order == nil {
			t.Fatalf("%s names no task_order_v3 vector", row["name"])
		}
		if row["task_hash"] != order["digest_hex"] {
			t.Fatalf("%s: task_hash is not the order digest", row["name"])
		}
		field := func(name string) map[string]any { return integratedField(t, order, name) }
		amount := func(name string) string {
			return field(name)["fields"].([]any)[0].(map[string]any)["utf8"].(string)
		}
		hrp, raw20, err := decodeBech32(row["message"].(map[string]any)["user"].(string))
		if err != nil || hrp != fixtureAddressHRP || hex.EncodeToString(raw20) != field("user_address")["hex"] {
			t.Fatalf("%s: user is not the order's user_address", row["name"])
		}
		want := map[string]string{
			"chainId":              field("chain_id")["utf8"].(string),
			"sessionId":            field("session_id")["hex"].(string),
			"orderSequence":        fmt.Sprint(field("order_sequence")["value"]),
			"modelId":              field("model_id")["hex"].(string),
			"profileVersion":       fmt.Sprint(field("profile_version")["value"]),
			"maxFee":               amount("max_fee"),
			"feeDenom":             doc["fee_denom"].(string),
			"earliestSubmitHeight": fmt.Sprint(field("earliest_submit_height")["value"]),
			"orderExpireHeight":    fmt.Sprint(field("order_expire_height")["value"]),
			"taskHash":             order["digest_hex"].(string),
		}
		for key, value := range want {
			if row["message"].(map[string]any)[key] != value {
				t.Fatalf("%s: message.%s is %v, the order has %s", row["name"], key, row["message"].(map[string]any)[key], value)
			}
		}
	}
}

// resolvePath walks a dotted member path through nested JSON objects.
func resolvePath(value any, path string) (any, bool) {
	for _, key := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		if value, ok = object[key]; !ok {
			return nil, false
		}
	}
	return value, true
}

// The registration chain vectors must be the golden projection with only the
// fields they claim to change, and each digest must frame the one before it.
func TestModelRegistrationChain(t *testing.T) {
	doc := loadIntegratedFixture(t, "hub", "model_registration_chain_v1.json")
	profile := loadIntegratedFixture(t, "hub", "model_profile_canonical_v3.json")
	manifest := loadIntegratedFixture(t, "hub", "model_manifest_v4.json")
	golden := profile["canonical_projection"].(map[string]any)
	manifestDigest := integratedVector(t, manifest, "TRUEOPEN_MODEL_MANIFEST_V4")["digest_hex"].(string)

	for key, source := range doc["manifest_projection"].(map[string]any) {
		path := source.(string)
		if strings.HasPrefix(path, "(") {
			continue
		}
		fromManifest, ok := resolvePath(manifest["manifest"], path)
		if !ok {
			t.Fatalf("manifest_projection %s names missing manifest member %s", key, path)
		}
		left, _ := canonicalJSONBytes(fromManifest)
		right, _ := canonicalJSONBytes(golden[key])
		if !bytes.Equal(left, right) {
			t.Fatalf("projection %s does not equal manifest %s", key, path)
		}
	}
	if len(doc["manifest_projection"].(map[string]any)) != len(golden) {
		t.Fatal("manifest_projection must name every projection field")
	}

	linked := false
	for _, raw := range doc["vectors"].([]any) {
		row := raw.(map[string]any)
		name := row["name"].(string)
		projection := row["projection"].(map[string]any)
		payload := decodeNumbers(t, projection["payload_utf8"].(string))
		encoded, err := canonicalJSONBytes(payload)
		if err != nil || string(encoded) != projection["payload_utf8"] {
			t.Fatalf("%s: projection payload is not canonical JSON", name)
		}
		if ref, ok := row["manifest"].(map[string]any); ok {
			linked = true
			if ref["digest_hex"] != manifestDigest || row["manifest_hash"] != manifestDigest {
				t.Fatalf("%s: manifest_hash is not the golden manifest digest", name)
			}
		}
		expected := map[string]any{}
		for key, value := range golden {
			expected[key] = value
		}
		expected["manifest_hash"] = "0x" + row["manifest_hash"].(string)
		expected["tool_call_parser"] = row["tool_call_parser"]
		expected["reasoning_parser"] = row["reasoning_parser"]
		want, _ := canonicalJSONBytes(expected)
		if !bytes.Equal(want, encoded) {
			t.Fatalf("%s: projection changes more than manifest_hash and the parser references", name)
		}
		for _, parser := range []string{"tool_call_parser", "reasoning_parser"} {
			ref := row[parser].(map[string]any)
			if len(ref) != 0 && (len(ref) != 2 || ref["name"] == "" || numberInt(t, ref["version"]) == 0) {
				t.Fatalf("%s: %s must be {} or a non-empty name with a positive version", name, parser)
			}
		}
		registration, err := canonicalJSONBytes(map[string]any{
			"chain_id":              doc["chain_id"],
			"chain_projection_hash": "0x" + projection["digest_hex"].(string),
			"manifest_hash":         "0x" + row["manifest_hash"].(string),
			"profile_version":       golden["profile_version"],
			"proposer_address":      doc["proposer_address"],
		})
		if err != nil || string(registration) != row["registration"].(map[string]any)["payload_utf8"] {
			t.Fatalf("%s: registration payload does not frame this projection digest", name)
		}
	}
	if !linked {
		t.Fatal("no vector is linked to the golden manifest")
	}
}

// protoBytesField encodes one length-delimited protobuf field.
func protoBytesField(number int, value []byte) []byte {
	out := protoVarint(uint64(number<<3 | 2))
	out = append(out, protoVarint(uint64(len(value)))...)
	return append(out, value...)
}

func protoVarint(value uint64) []byte {
	var out []byte
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

// The DIRECT vector's SignDoc and TxRaw are re-encoded from their parts, and
// the signature must be the 64-byte low-S form. The keccak256 digest and the
// signature itself are not recomputed here: this module carries no keccak or
// secp256k1 implementation.
func TestDirectSignModeVectorStructure(t *testing.T) {
	account := loadIntegratedFixture(t, "shared", "account_signing_v1.json")
	direct := account["direct_sign_mode_transaction"].(map[string]any)
	decode := func(key string) []byte {
		raw, err := hex.DecodeString(direct[key].(string))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	body, auth := decode("body_bytes_hex"), decode("auth_info_bytes_hex")
	accountNumber, err := strconv.ParseUint(direct["account_number"].(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	signDoc := append(protoBytesField(1, body), protoBytesField(2, auth)...)
	signDoc = append(signDoc, protoBytesField(3, []byte(direct["chain_id"].(string)))...)
	signDoc = append(signDoc, append(protoVarint(4<<3), protoVarint(accountNumber)...)...)
	if !bytes.Equal(signDoc, decode("sign_doc_bytes_hex")) {
		t.Fatal("sign_doc_bytes is not SignDoc{body_bytes, auth_info_bytes, chain_id, account_number}")
	}
	signature := decode("signature_64")
	txRaw := append(append(protoBytesField(1, body), protoBytesField(2, auth)...), protoBytesField(3, signature)...)
	if !bytes.Equal(txRaw, decode("tx_raw_hex")) {
		t.Fatal("tx_raw is not TxRaw{body_bytes, auth_info_bytes, [signature_64]}")
	}
	order, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	s := new(big.Int).SetBytes(signature[32:])
	if len(signature) != 64 || s.Sign() == 0 || s.Cmp(new(big.Int).Rsh(order, 1)) > 0 {
		t.Fatal("signature_64 must be 64 bytes with a low S")
	}
	pub, _ := hex.DecodeString(account["account"].(map[string]any)["pub_compressed"].(string))
	pubAny := protoBytesField(1, pub)
	if hex.EncodeToString(pubAny) != direct["pubkey_any_value_hex"] {
		t.Fatal("pubkey_any_value is not PubKey{key: the account's compressed key}")
	}
	typeURL := direct["pubkey_type_url"].(string)
	if typeURL != account["upstream"].(map[string]any)["pubkey_type_url"] ||
		!bytes.Contains(auth, append(protoBytesField(1, []byte(typeURL)), protoBytesField(2, pubAny)...)) {
		t.Fatal("auth_info does not carry the account key under the published type URL")
	}
	if !bytes.Contains(body, []byte(direct["msg_type_url"].(string))) || !bytes.Contains(body, []byte(direct["signer_address"].(string))) {
		t.Fatal("body does not carry the message and its signer")
	}
}

// REST bodies: proto field names only, and every bytes placeholder in exactly
// one of the two published encodings.
func TestRESTJSONShapes(t *testing.T) {
	doc := loadIntegratedFixture(t, "shared", "rest_json_shapes_v1.json")
	hexPlaceholder := strings.Repeat("ab", 32)
	base64Placeholder := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	var counts [2]int
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if strings.ToLower(key) != key {
					t.Fatalf("%s.%s is not a proto field name", path, key)
				}
				walk(path+"."+key, child)
			}
		case []any:
			for index, child := range typed {
				walk(fmt.Sprintf("%s[%d]", path, index), child)
			}
		case string:
			switch {
			case typed == hexPlaceholder:
				counts[0]++
			case typed == base64Placeholder:
				counts[1]++
			case strings.Contains(typed, "abab") || strings.HasPrefix(typed, "0x"):
				t.Fatalf("%s: bytes value %q is neither lowercase hex nor Base64", path, typed)
			}
		}
	}
	for _, raw := range doc["responses"].([]any) {
		row := raw.(map[string]any)
		walk(row["name"].(string), row["body"])
	}
	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("expected both hex and Base64 bytes in the bodies, got %v", counts)
	}
}
