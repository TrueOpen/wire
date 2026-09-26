package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func supportModelFields(ids ...map[string]any) []any {
	count := map[string]any{"name": "model_count", "type": "uint32", "value": json.Number("2")}
	nested := []any{map[string]any{"name": "element_count", "type": "uint32", "value": json.Number("2")}}
	for _, id := range ids {
		nested = append(nested, id)
	}
	return []any{count, map[string]any{"name": "models", "type": "frame", "fields": nested}}
}

func rawModelID(value byte) map[string]any {
	return map[string]any{"type": "bytes", "hex": strings.Repeat(fmt.Sprintf("%02x", value), 32)}
}

func TestSupportModelVectorsRequireOrderedRawHash32(t *testing.T) {
	first, second := rawModelID(1), rawModelID(2)
	for _, test := range []struct {
		name string
		ids  []map[string]any
		want string
	}{
		{name: "valid", ids: []map[string]any{first, second}},
		{name: "text", ids: []map[string]any{{"type": "string", "utf8": "model-a"}, second}, want: "raw Hash32"},
		{name: "short", ids: []map[string]any{{"type": "bytes", "hex": strings.Repeat("01", 31)}, second}, want: "exactly 32 bytes"},
		{name: "count mismatch", ids: []map[string]any{first}, want: "counts do not match"},
		{name: "duplicate", ids: []map[string]any{first, first}, want: "strictly ascending"},
		{name: "descending", ids: []map[string]any{second, first}, want: "strictly ascending"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := supportModelFields(test.ids...)
			for _, domain := range []string{"TRUEOPEN_SUPPORT_MODELS_V1", "TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1"} {
				candidate := fields
				if domain == "TRUEOPEN_DAILY_SUPPORT_CONFIRMATION_V1" {
					candidate = append([]any{nil, nil, nil, nil, nil}, fields...)
				}
				err := validateSupportModelFields(domain, candidate)
				if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
					t.Fatalf("%s: got %v, want %q", domain, err, test.want)
				}
			}
		})
	}
}

func TestHubParamsVectorPublishesPositiveStakeGracePeriod(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/v1/shared/params_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	for _, rawVector := range document["vectors"].([]any) {
		vector := rawVector.(map[string]any)
		if vector["name"] != "hub_params_v2" {
			continue
		}
		params := vector["fields"].([]any)[2].(map[string]any)
		for _, rawBucket := range params["fields"].([]any) {
			bucket := rawBucket.(map[string]any)
			if bucket["name"] != "service" {
				continue
			}
			fields := bucket["fields"].([]any)
			last := fields[len(fields)-1].(map[string]any)
			value, err := publishedUint(last["value"])
			if last["name"] != "min_stake_grace_period_blocks" || last["type"] != "uint64" || err != nil || value == 0 {
				t.Fatalf("service parameter 22 must be a positive uint64 grace period")
			}
			return
		}
	}
	t.Fatal("HubParamsV2 service parameter bucket not found")
}
