package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// The published fixtures must pass as they are.
func TestPublishedFixturesAreSelfConsistent(t *testing.T) {
	got, err := verifyRoot("../../testdata/v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.bases == 0 || got.tampers == 0 || got.replays == 0 || got.mutations == 0 || got.accounting == 0 ||
		got.keys == 0 || got.domains == 0 || got.eip712 == 0 || got.signatures == 0 || got.negatives == 0 {
		t.Fatalf("a check ran over nothing: %+v", got)
	}
}

// selectorVector is a two-field H_FIELDS_V1 vector with one tamper and one
// replay row, all computed correctly.
func selectorVector() map[string]any {
	fields := []any{
		map[string]any{"name": "chain_id", "type": "string", "utf8": "chain-1"},
		map[string]any{"name": "model_id", "type": "bytes", "hex": strings.Repeat("55", 32)},
	}
	parts, err := encodeFields(fields)
	if err != nil {
		panic(err)
	}
	base := hFields("TRUEOPEN_TEST_V1", parts)
	tampered := cloneParts(parts)
	tampered[1][31] ^= 1
	replayed := cloneParts(parts)
	replayed[0] = []byte("chain-2")
	return map[string]any{
		"name":         "selector",
		"domain":       "TRUEOPEN_TEST_V1",
		"framing":      "H_FIELDS_V1",
		"fields":       fields,
		"preimage_hex": hex.EncodeToString(base),
		"digest_hex":   digestHex(base),
		"tamper": []any{map[string]any{
			"name": "model_id_last_byte", "field": 1, "byte": -1, "bit": 0, "digest_hex": digestHex(hFields("TRUEOPEN_TEST_V1", tampered)),
		}},
		"replay": []any{map[string]any{
			"name": "cross_chain", "field": 0, "value": "chain-2", "digest_hex": digestHex(hFields("TRUEOPEN_TEST_V1", replayed)),
		}},
	}
}

func run(t *testing.T, document any) []string {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	_, problems := verifyFile("test.json", raw)
	return problems
}

func requireProblem(t *testing.T, problems []string, fragment string) {
	t.Helper()
	for _, problem := range problems {
		if strings.Contains(problem, fragment) {
			return
		}
	}
	t.Fatalf("no problem mentions %q; got %v", fragment, problems)
}

func TestCorrectVectorPasses(t *testing.T) {
	if problems := run(t, map[string]any{"vectors": []any{selectorVector()}}); len(problems) != 0 {
		t.Fatal(problems)
	}
}

// A replay row left behind when the base's encoding changed: the base
// recomputes, the row does not.
func TestStaleReplayDigestFails(t *testing.T) {
	vector := selectorVector()
	vector["replay"].([]any)[0].(map[string]any)["digest_hex"] = strings.Repeat("00", 32)
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), `replay "cross_chain" recomputes to`)
}

func TestStaleTamperDigestFails(t *testing.T) {
	vector := selectorVector()
	vector["tamper"].([]any)[0].(map[string]any)["bit"] = 1
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), `tamper "model_id_last_byte" recomputes to`)
}

func TestStaleBaseDigestFails(t *testing.T) {
	vector := selectorVector()
	vector["digest_hex"] = strings.Repeat("00", 32)
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), "fields hash to")
}

// mutationVector adds one mutation row per edit op to the selector vector,
// each with the digest its edit produces.
func mutationVector() map[string]any {
	vector := selectorVector()
	chain := []byte("chain-1")
	model := make([]byte, 32)
	for index := range model {
		model[index] = 0x55
	}
	edited := append([]byte(nil), model...)
	edited[31] ^= 1
	digest := func(parts ...[]byte) string { return digestHex(hFields("TRUEOPEN_TEST_V1", parts)) }
	vector["mutations"] = []any{
		map[string]any{"name": "replace", "digest_hex": digest(chain, edited), "edit": map[string]any{
			"op": "replace", "path": "model_id", "field": map[string]any{"name": "model_id", "type": "bytes", "hex": hex.EncodeToString(edited)},
		}},
		map[string]any{"name": "swap", "digest_hex": digest(model, chain), "edit": map[string]any{
			"op": "swap", "paths": []any{"chain_id", "model_id"},
		}},
		map[string]any{"name": "remove", "digest_hex": digest(chain), "edit": map[string]any{"op": "remove", "path": "model_id"}},
		map[string]any{"name": "append", "digest_hex": digest(chain, model, []byte{0, 0, 0, 1}), "edit": map[string]any{
			"op": "append", "field": map[string]any{"name": "__extra", "type": "uint32", "value": json.Number("1")},
		}},
		map[string]any{"name": "prose_only", "digest_hex": strings.Repeat("00", 32), "change": "not recomputable"},
	}
	return vector
}

func TestMutationEditsRecompute(t *testing.T) {
	if problems := run(t, map[string]any{"vectors": []any{mutationVector()}}); len(problems) != 0 {
		t.Fatal(problems)
	}
}

func TestStaleMutationDigestFails(t *testing.T) {
	vector := mutationVector()
	vector["mutations"].([]any)[1].(map[string]any)["digest_hex"] = strings.Repeat("00", 32)
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), `mutation "swap" recomputes to`)
}

func TestMutationEditErrorsFail(t *testing.T) {
	for name, edit := range map[string]map[string]any{
		"unknown edit op":             {"op": "rename"},
		`no field "missing"`:          {"op": "remove", "path": "missing"},
		"is not a frame":              {"op": "remove", "path": "chain_id.inner"},
		"two distinct fields":         {"op": "swap", "paths": []any{"chain_id", "chain_id"}},
		"replace needs a typed field": {"op": "replace", "path": "chain_id"},
	} {
		vector := mutationVector()
		vector["mutations"].([]any)[0].(map[string]any)["edit"] = edit
		requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), name)
	}
}

// An edit that changes nothing is not a mutation, whatever digest it claims.
func TestMutationEditThatChangesNothingFails(t *testing.T) {
	vector := mutationVector()
	vector["mutations"].([]any)[0].(map[string]any)["edit"] = map[string]any{
		"op": "replace", "path": "chain_id", "field": map[string]any{"name": "chain_id", "type": "string", "utf8": "chain-1"},
	}
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), "leaves the base digest unchanged")
}

func TestDuplicateVectorNameFails(t *testing.T) {
	first, second := selectorVector(), selectorVector()
	requireProblem(t, run(t, map[string]any{"vectors": []any{first, second}}), `reuses the name "selector"`)
}

func TestRowWithDigestButNoTypedFieldsFails(t *testing.T) {
	vector := map[string]any{
		"name": "opaque", "domain": "TRUEOPEN_TEST_V1", "framing": "H_V1",
		"tamper": []any{map[string]any{"name": "t", "field": 0, "byte": 0, "bit": 0, "digest_hex": strings.Repeat("00", 32)}},
	}
	requireProblem(t, run(t, map[string]any{"vectors": []any{vector}}), "no typed H_FIELDS_V1 fields")
}

// leafTree is a params-shaped vector: chain_id and params_version scope the
// commitment, and the params frame holds 3 scalars, one submessage and one
// repeated field of two submessage elements.
func leafTree(accounting map[string]any) map[string]any {
	element := func(value int) map[string]any {
		return map[string]any{"name": "element", "type": "frame", "fields": []any{
			map[string]any{"name": "value", "type": "uint32", "value": json.Number(strconv.Itoa(value))},
		}}
	}
	return map[string]any{
		"name": "params", "leaf_accounting": accounting,
		"fields": []any{
			map[string]any{"name": "chain_id", "type": "string", "utf8": "chain-1"},
			map[string]any{"name": "params_version", "type": "uint64", "value": json.Number("7")},
			map[string]any{"name": "params", "type": "frame", "fields": []any{
				map[string]any{"name": "a", "type": "uint32", "value": json.Number("1")},
				map[string]any{"name": "nested", "type": "frame", "fields": []any{
					map[string]any{"name": "b", "type": "uint64", "value": json.Number("2")},
				}},
				map[string]any{"name": "list", "type": "frame", "fields": []any{
					map[string]any{"name": "element_count", "type": "uint32", "value": json.Number("2")},
					element(3), element(4),
				}},
			}},
		},
	}
}

func TestLeafAccounting(t *testing.T) {
	// Scalars a, b and the two element values; submessages nested and the two
	// elements; one repeated field. element_count, chain_id and params_version
	// are not counted.
	good := map[string]any{"scalars": 4, "submessages": 3, "repeated": 1}
	if problems := run(t, map[string]any{"vectors": []any{leafTree(good)}}); len(problems) != 0 {
		t.Fatal(problems)
	}
	bad := map[string]any{"scalars": 5, "submessages": 4, "repeated": 1}
	problems := run(t, map[string]any{"vectors": []any{leafTree(bad)}})
	requireProblem(t, problems, "leaf_accounting.scalars is 5, the field tree has 4")
	requireProblem(t, problems, "leaf_accounting.submessages is 4, the field tree has 3")
}
