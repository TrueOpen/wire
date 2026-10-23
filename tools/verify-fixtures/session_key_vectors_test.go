package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/TrueOpen/wire/tools/internal/eip712"
)

// These checks evaluate the published authorization boundary, not a Keeper
// implementation: canonical anchors and non-authorization admission checks are
// explicit fixture preconditions. Real signatures must still recover to the
// key selected by each row; a changed typed message cannot pass as a key switch.
type sessionKeyState struct {
	Status       string `json:"status"`
	Owner        string `json:"owner"`
	Key          string `json:"key"`
	Expiry       uint64 `json:"expiry"`
	SetHeight    uint64 `json:"set_height"`
	Cap          string `json:"cap"`
	Spent        string `json:"spent"`
	NextSequence uint64 `json:"next_sequence"`
}

func sessionFixture(t *testing.T) map[string]any {
	t.Helper()
	return loadIntegratedFixture(t, "task", "session_key_authorization_v1.json")
}

func decodeSessionRow(t *testing.T, raw any, out any) {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

func sessionAmount(text string) uint64 {
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != text {
		panic("noncanonical fixture amount: " + text)
	}
	return value
}

func recoverSection(t *testing.T, section map[string]any) string {
	t.Helper()
	d := section["domain"].(map[string]any)
	separator, err := (eip712.Domain{Name: d["name"].(string), Version: d["version"].(string), ChainID: d["chain_id"].(string)}).Separator()
	if err != nil {
		t.Fatal(err)
	}
	primary, types, err := eip712.ParseEncodeType(section["encode_type"].(string))
	if err != nil {
		t.Fatal(err)
	}
	hs, err := types.HashStruct(primary, section["message"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	digest := eip712.SigningDigest(separator, hs)
	signature, err := hex.DecodeString(section["signature_65"].(string))
	if err != nil {
		t.Fatal(err)
	}
	address, err := eip712.Recover(digest, signature)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(address[:])
}

func TestSessionKeyOrderAdmissionVectors(t *testing.T) {
	doc := sessionFixture(t)
	payload := doc["order_payload"].(map[string]any)
	fields := payload["fields"].([]any)
	values := map[string]map[string]any{}
	for _, raw := range fields {
		f := raw.(map[string]any)
		values[f["name"].(string)] = f
	}
	anchor := uint64(numberInt(t, values["session_anchor_height"]["value"]))
	owner := doc["account"].(map[string]any)["address_bytes"].(string)
	for _, raw := range doc["admission_cases"].([]any) {
		var row struct {
			Name            string          `json:"name"`
			Order           string          `json:"order"`
			Height          uint64          `json:"current_height"`
			Anchor          uint64          `json:"anchor_height"`
			State           sessionKeyState `json:"state"`
			Expected        string          `json:"expected"`
			ExpectedSpent   string          `json:"expected_spent"`
			AlreadyAdmitted bool            `json:"already_admitted"`
			LaterValid      *bool           `json:"later_admission_valid"`
		}
		decodeSessionRow(t, raw, &row)
		t.Run(row.Name, func(t *testing.T) {
			section := doc[row.Order].(map[string]any)
			message := section["message"].(map[string]any)
			if message["taskHash"] != payload["digest_hex"] || row.Anchor != anchor {
				t.Fatal("authorization context is not bound to the signed order payload")
			}
			if message["user"] != doc["account"].(map[string]any)["account_bech32"] ||
				message["sessionId"] != values["session_id"]["hex"] ||
				message["orderSequence"] != values["order_sequence"]["value"].(json.Number).String() ||
				message["maxFee"] != values["max_fee"]["fields"].([]any)[0].(map[string]any)["utf8"] {
				t.Fatal("typed authorization fields differ from the full order")
			}
			signatureAddress := recoverSection(t, section)
			fee := sessionAmount(message["maxFee"].(string))
			spent := sessionAmount(row.State.Spent)
			cap := sessionAmount(row.State.Cap)
			sequence := sessionAmount(message["orderSequence"].(string))
			got := "ACCEPT_SESSION_KEY"
			after := spent
			switch {
			case row.AlreadyAdmitted:
				got = "ALREADY_ADMITTED"
			case row.State.Status == "CLOSED":
				got = "SESSION_CLOSED"
			case row.State.Owner != owner:
				got = "OWNER_MISMATCH"
			case sequence != row.State.NextSequence:
				got = "SEQUENCE_MISMATCH"
			case signatureAddress == owner:
				got = "ACCEPT_WALLET"
			case row.State.Key == "":
				got = "ERR_SESSION_KEY_INVALID"
			case signatureAddress != row.State.Key || row.Anchor < row.State.SetHeight:
				got = "ERR_SESSION_KEY_INVALID"
			case row.Height > row.State.Expiry:
				got = "ERR_SESSION_KEY_EXPIRED"
			case cap != 0 && fee > math.MaxUint64-spent:
				got = "ERR_SESSION_KEY_SPEND_CAP_EXCEEDED"
			case fee > math.MaxUint64-spent:
				got = "AMOUNT_OVERFLOW"
			case cap != 0 && spent+fee > cap:
				got = "ERR_SESSION_KEY_SPEND_CAP_EXCEEDED"
			case row.LaterValid != nil && !*row.LaterValid:
				got = "LATER_ADMISSION_REJECTED"
			default:
				after += fee
			}
			if got != row.Expected || strconv.FormatUint(after, 10) != row.ExpectedSpent {
				t.Fatalf("got %s spent=%d, want %s spent=%s", got, after, row.Expected, row.ExpectedSpent)
			}
		})
	}
}

func TestSessionKeyUpdateVectors(t *testing.T) {
	doc := sessionFixture(t)
	for _, raw := range doc["update_cases"].([]any) {
		var row struct {
			Name      string          `json:"name"`
			Height    uint64          `json:"current_height"`
			MaxBlocks uint64          `json:"current_max_blocks"`
			Signer    string          `json:"signer"`
			Action    string          `json:"action"`
			State     sessionKeyState `json:"state"`
			Grant     struct {
				Key    string `json:"key"`
				Expiry uint64 `json:"expiry"`
				Cap    string `json:"cap"`
			} `json:"grant"`
			Expected      string          `json:"expected"`
			ExpectedState sessionKeyState `json:"expected_state"`
		}
		decodeSessionRow(t, raw, &row)
		t.Run(row.Name, func(t *testing.T) {
			next := row.State
			got := "APPLIED"
			key, err := hex.DecodeString(row.Grant.Key)
			switch {
			case row.State.Status == "CLOSED":
				got = "SESSION_CLOSED"
			case row.Signer != row.State.Owner:
				got = "UNAUTHORIZED"
			case row.Action != "set" && row.Action != "clear":
				got = "ACTION_REQUIRED"
			case row.Action == "clear":
				next.Key = ""
				next.Expiry = 0
				next.Cap = "0"
				next.SetHeight = 0
			case err != nil || len(key) != 20 || bytes.Equal(key, make([]byte, 20)) || row.Grant.Key == row.State.Owner || row.MaxBlocks == 0 || row.MaxBlocks > math.MaxUint64-row.Height || row.Grant.Expiry <= row.Height || row.Grant.Expiry > row.Height+row.MaxBlocks:
				got = "ERR_SESSION_KEY_INVALID"
			default:
				if next.Key != row.Grant.Key {
					next.SetHeight = row.Height
				}
				next.Key = row.Grant.Key
				next.Expiry = row.Grant.Expiry
				next.Cap = row.Grant.Cap
			}
			if got == "APPLIED" && next == row.State {
				got = "NOOP"
			}
			if got != row.Expected || next != row.ExpectedState {
				t.Fatalf("got %s %+v, want %s %+v", got, next, row.Expected, row.ExpectedState)
			}
		})
	}
}

func TestRegisteredRequestVectorsDoNotCarryGrant(t *testing.T) {
	doc := sessionFixture(t)
	key := doc["session_key"].(map[string]any)["address_bytes"]
	for _, name := range []string{"registered_sdk_request", "registered_data_request"} {
		section := doc[name].(map[string]any)
		if recoverSection(t, section) != key {
			t.Fatal(name + ": wrong signer")
		}
		message := section["message"].(map[string]any)
		if message["sessionGrantHash"] != strings.Repeat("0", 64) {
			t.Fatal(name + ": must bind no grant")
		}
		bodyName := "registered_open_task_body"
		if name == "registered_data_request" {
			bodyName = "registered_output_metadata_body"
		}
		body := doc[bodyName].(map[string]any)
		if message["bodyDigest"] != body["digest_hex"] {
			t.Fatal(name + ": signature does not bind its body")
		}
		if name == "registered_data_request" {
			ref := body["fields"].([]any)[0].(map[string]any)["fields"].([]any)
			if numberInt(t, ref[3].(map[string]any)["value"]) != 2 ||
				ref[0].(map[string]any)["hex"] != doc["order_payload"].(map[string]any)["digest_hex"] {
				t.Fatal("registered data request must bind this order's OUTPUT object")
			}
		}
	}
}

func TestRegisteredRequestAuthorizationOrderingVectors(t *testing.T) {
	doc := sessionFixture(t)
	rows := doc["registered_request_cases"].([]any)
	if len(rows) != 18 {
		t.Fatal("missing registered request authorization cases")
	}
	for _, raw := range rows {
		var row struct {
			Name     string `json:"name"`
			Base     string `json:"base"`
			Expected string `json:"expected"`
			State    struct {
				Chain  bool   `json:"chain_available"`
				Exists bool   `json:"session_exists"`
				Status string `json:"status"`
				Owner  bool   `json:"owner_matches"`
				Key    bool   `json:"key_matches"`
				Height uint64 `json:"current_height"`
				Expiry uint64 `json:"expiry_height"`
				Method bool   `json:"method_allowed"`
				Local  bool   `json:"local_task_found"`
				Output bool   `json:"output_object"`
			} `json:"state"`
		}
		decodeSessionRow(t, raw, &row)
		t.Run(row.Name, func(t *testing.T) {
			recovered := recoverSection(t, doc[row.Base].(map[string]any))
			if recovered != doc["session_key"].(map[string]any)["address_bytes"] {
				t.Fatal("base signature is not the registered key")
			}
			data := row.Base == "registered_data_request"
			prefix := "SDK_AUTH_"
			if data {
				prefix = "DATA_ACCESS_"
			}
			got := "ACCEPT"
			switch {
			case !row.State.Chain || data && !row.State.Local || !row.State.Exists || row.State.Status == "CLOSED" || !row.State.Owner || !row.State.Key:
				got = prefix + "INVALID_SIGNATURE"
			case row.State.Height > row.State.Expiry:
				got = prefix + "SESSION_GRANT_EXPIRED"
			case !row.State.Method || data && !row.State.Output:
				got = prefix + "SESSION_METHOD_NOT_ALLOWED"
			}
			if got != row.Expected {
				t.Fatalf("got %s, want %s", got, row.Expected)
			}
		})
	}
}
