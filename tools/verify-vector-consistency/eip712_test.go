package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// A cross-domain replay row hashes the unchanged fields under another domain.
func TestCrossDomainReplay(t *testing.T) {
	vector := selectorVector()
	parts, _ := encodeFields(vector["fields"].([]any))
	row := map[string]any{"name": "cross_domain", "domain": "TRUEOPEN_OTHER_V1", "digest_hex": digestHex(hFields("TRUEOPEN_OTHER_V1", parts))}
	vector["replay"] = append(vector["replay"].([]any), row)
	if problems := run(t, map[string]any{"vectors": []any{vector}}); len(problems) != 0 {
		t.Fatal(problems)
	}
	row["digest_hex"] = vector["digest_hex"]
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), `replay "cross_domain" recomputes to`)
	row["domain"] = "TRUEOPEN_TEST_V1"
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), "domain must name another TRUEOPEN_ domain")
}

// accountSigning loads the published EIP-712 fixture, which must pass as is.
func accountSigning(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/v1/shared/account_signing_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	if problems := run(t, document); len(problems) != 0 {
		t.Fatal(problems)
	}
	return document
}

func negativeRow(t *testing.T, document map[string]any, name string) map[string]any {
	t.Helper()
	for _, raw := range document["request_auth_negative_cases"].([]any) {
		if row := raw.(map[string]any); row["name"] == name {
			return row
		}
	}
	t.Fatalf("no negative row %s", name)
	return nil
}

func TestEIP712ValuesAreRecomputed(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(map[string]any)
		fragment string
	}{
		{"stale hash_struct", func(d map[string]any) {
			d["sdk_request"].(map[string]any)["hash_struct"] = strings.Repeat("00", 32)
		}, "sdk_request: hash_struct is"},
		{"message edited without its digests", func(d map[string]any) {
			d["session_grant"].(map[string]any)["message"].(map[string]any)["expiryHeight"] = "1501"
		}, "session_grant: signing_digest is"},
		{"domain version edited", func(d map[string]any) {
			d["task_data_request"].(map[string]any)["domain"].(map[string]any)["version"] = "1"
		}, "task_data_request.domain: domain_separator is"},
		{"signature of another section", func(d map[string]any) {
			d["sdk_request"].(map[string]any)["signature_65"] = d["sdk_request_session"].(map[string]any)["signature_65"]
		}, "sdk_request: recovered_address is"},
		{"signer that did not sign", func(d map[string]any) {
			d["sdk_request_session"].(map[string]any)["signer"] = "account"
		}, "is not the RFC 6979 signature of account"},
		{"key block address", func(d map[string]any) {
			key := d["session_key"].(map[string]any)
			key["address_0x"] = strings.ToLower(key["address_0x"].(string))
		}, "session_key: address_0x is"},
		{"amino transaction", func(d map[string]any) {
			tx := d["msg_create_session_transaction"].(map[string]any)
			tx["canonical_amino_json"] = strings.Replace(tx["canonical_amino_json"].(string), `"sequence":"9"`, `"sequence":"10"`, 1)
		}, "msg_create_session_transaction: hash_struct is"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := accountSigning(t)
			tc.mutate(document)
			requireProblem(t, run(t, document), tc.fragment)
		})
	}
}

func TestNegativeRequestRowsAreRecomputed(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(map[string]any)
		fragment string
	}{
		{"recovered address of a verified row", func(d map[string]any) {
			negativeRow(t, d, "sdk_request_other_chain_id")["recovered_address"] = d["account"].(map[string]any)["address_bytes"]
		}, "[sdk_request_other_chain_id]: recovered_address is"},
		{"signature of a signed row", func(d map[string]any) {
			row := negativeRow(t, d, "open_task_with_session_grant")
			row["signed"].(map[string]any)["signer"] = "wrong_key"
		}, "[open_task_with_session_grant]: signature_65 is"},
		{"edit naming no member", func(d map[string]any) {
			negativeRow(t, d, "sdk_request_other_evm_chain_id")["verified"] = map[string]any{"message": map[string]any{"chain": "x"}}
		}, `edit names "chain"`},
		{"window decision", func(d map[string]any) {
			negativeRow(t, d, "session_grant_window_upper_edge")["expect"] = "reject"
		}, "gives accept=true, the row expects reject"},
		{"unknown base", func(d map[string]any) {
			negativeRow(t, d, "sdk_request_expiry_zero")["base"] = "nothing"
		}, `base "nothing" is not a typed section`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := accountSigning(t)
			tc.mutate(document)
			requireProblem(t, run(t, document), tc.fragment)
		})
	}
}
