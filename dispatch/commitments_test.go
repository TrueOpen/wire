package dispatch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cosmos/btcutil/bech32"
)

type projectionField struct {
	Name   string            `json:"name"`
	Value  json.Number       `json:"value"`
	Hex    string            `json:"hex"`
	Bech32 string            `json:"bech32"`
	UTF8   string            `json:"utf8"`
	Fields []projectionField `json:"fields"`
}

func selectedField(t *testing.T, fields []projectionField, name string) projectionField {
	t.Helper()
	for _, field := range fields {
		if field.Name == name {
			return field
		}
	}
	t.Fatalf("missing %s", name)
	return projectionField{}
}

func fieldUint(t *testing.T, f projectionField) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(f.Value.String(), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func fieldAddress(t *testing.T, f projectionField) string {
	t.Helper()
	if f.Bech32 != "" {
		return f.Bech32
	}
	if f.Hex == "" {
		return ""
	}
	bits, err := bech32.ConvertBits(hexBytes(t, f.Hex), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	address, err := bech32.Encode("trueopen", bits)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func TestPublishedPoolRosterAndAllChallengeScopes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Name   string            `json:"name"`
			Domain string            `json:"domain"`
			Digest string            `json:"digest_hex"`
			Fields []projectionField `json:"fields"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	covered := map[string]int{}
	for _, row := range doc.Vectors {
		if row.Domain != "TRUEOPEN_DISPATCH_POOL_V1" && row.Domain != "TRUEOPEN_DISPATCH_ROSTER_V1" && row.Domain != "TRUEOPEN_DISPATCH_CHALLENGE_ID_V1" {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			get := func(name string) projectionField { return selectedField(t, row.Fields, name) }
			chain := get("chain_id").UTF8
			var digest [32]byte
			if row.Domain == "TRUEOPEN_DISPATCH_CHALLENGE_ID_V1" {
				scope := ChallengeScope{TaskID: array32(t, get("task_id").Hex), Kind: uint32(fieldUint(t, get("challenge_kind"))), DispatchRound: uint32(fieldUint(t, get("dispatch_round_or_zero"))), AttemptRank: uint32(fieldUint(t, get("attempt_rank_or_zero"))), VictimOperator: fieldAddress(t, get("victim_operator_or_empty")), BuilderAddress: fieldAddress(t, get("builder_address_or_empty")), DispatchRecordHash: array32(t, get("dispatch_record_hash_or_zero32").Hex), ChallengerAddress: fieldAddress(t, get("challenger_address"))}
				digest, err = ChallengeID(chain, scope)
				if scope.Kind != 5 {
					bad := scope
					bad.BuilderAddress = scope.ChallengerAddress
					if _, e := ChallengeID(chain, bad); e == nil {
						t.Fatal("irrelevant Builder creates another challenge ID")
					}
				}
			} else {
				list := get("members").Fields
				var members []RosterMember
				for _, item := range list[1:] {
					f := func(n string) projectionField { return selectedField(t, item.Fields, n) }
					members = append(members, RosterMember{uint32(fieldUint(t, f("slot"))), fieldUint(t, f("slot_version")), fieldAddress(t, f("operator_address")), fieldUint(t, f("candidate_weight"))})
				}
				if fieldUint(t, list[0]) != uint64(len(members)) {
					t.Fatal("fixture member count mismatch")
				}
				if row.Domain == "TRUEOPEN_DISPATCH_POOL_V1" {
					digest, err = PoolDigest(chain, array32(t, get("candidate_pool_snapshot_id").Hex), fieldUint(t, get("reference_height")), array32(t, get("model_id").Hex), uint32(fieldUint(t, get("profile_version"))), members)
				} else {
					digest, err = RosterDigest(chain, array32(t, get("task_id").Hex), fieldUint(t, get("reference_height")), array32(t, get("candidate_pool_snapshot_id").Hex), members)
				}
			}
			if err != nil || hex.EncodeToString(digest[:]) != row.Digest {
				t.Fatal("shared commitment differs from independent vector", err)
			}
			covered[row.Domain]++
		})
	}
	if covered["TRUEOPEN_DISPATCH_POOL_V1"] != 1 || covered["TRUEOPEN_DISPATCH_ROSTER_V1"] != 1 || covered["TRUEOPEN_DISPATCH_CHALLENGE_ID_V1"] != 5 {
		t.Fatal("missing commitment/scope vector")
	}
}

func TestMemberCommitmentsRejectAmbiguousSets(t *testing.T) {
	a, b := account(t, 1), account(t, 2)
	for _, members := range [][]RosterMember{{{2, 1, a, 1}, {1, 1, b, 1}}, {{1, 1, a, 1}, {1, 1, b, 1}}, {{1, 1, a, 1}, {2, 1, a, 1}}, {{1, 0, a, 1}}, {{1, 1, a, 0}}, {{1, 1, "invalid", 1}}} {
		if _, err := RosterDigest("chain", [32]byte{}, 1, [32]byte{}, members); err == nil {
			t.Fatal("noncanonical member set admitted")
		}
		if _, err := PoolDigest("chain", [32]byte{}, 1, [32]byte{}, 1, members); err == nil {
			t.Fatal("noncanonical pool admitted")
		}
	}
	for _, scope := range []ChallengeScope{{Kind: 0, ChallengerAddress: a}, {Kind: 1, ChallengerAddress: a}, {Kind: 5, ChallengerAddress: a, BuilderAddress: b}, {Kind: 3, DispatchRound: 1, ChallengerAddress: a}, {Kind: 4, AttemptRank: 1, ChallengerAddress: a}, {Kind: 2, ChallengerAddress: "invalid"}} {
		if _, err := ChallengeID("chain", scope); err == nil {
			t.Fatal("ambiguous challenge scope admitted")
		}
	}
	first, _ := memberCommitment([]RosterMember{{1, 1, a, 1}})
	second, _ := memberCommitment([]RosterMember{{1, 1, b, 1}})
	if bytes.Equal(first, second) {
		t.Fatal("operator bytes not committed")
	}
}
