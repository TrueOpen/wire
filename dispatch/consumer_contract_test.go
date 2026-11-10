package dispatch

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func readConsumerFixture(t *testing.T, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "dispatch_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func publishedByName(t *testing.T, name string) publishedVector {
	t.Helper()
	for _, row := range published(t) {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("missing vector %s", name)
	return publishedVector{}
}

func TestEpochSeedDerivationUsesExactVerifiedStartBeacon(t *testing.T) {
	var doc struct {
		Source struct {
			Length       uint64 `json:"epoch_length_blocks"`
			Height       uint64 `json:"earliest_submit_height"`
			Epoch        uint64 `json:"epoch"`
			Start        uint64 `json:"epoch_start_height"`
			BeaconHeight uint64 `json:"beacon_height"`
			Verified     bool   `json:"beacon_verified"`
			Beacon       string `json:"beacon_randomness_hex"`
			Seed         string `json:"epoch_seed_hex"`
			AlphaVector  string `json:"alpha_vector"`
			Alpha        string `json:"alpha_hex"`
			Proof        string `json:"vrf_proof_hex"`
		} `json:"epoch_seed_derivation"`
		VRF struct {
			PublicKey  string `json:"public_key_hex"`
			Randomness string `json:"randomness_hex"`
		} `json:"vrf"`
	}
	readConsumerFixture(t, &doc)
	s := doc.Source
	seed, err := ResolveEpochSeed(s.Height, s.Length, s.BeaconHeight, hexBytes(t, s.Beacon), s.Verified)
	if err != nil {
		t.Fatal(err)
	}
	if seed.Epoch != s.Epoch || seed.ReferenceHeight != s.Start || hex.EncodeToString(seed.Randomness[:]) != s.Seed {
		t.Fatal("epoch source derivation differs")
	}
	row := publishedByName(t, s.AlphaVector)
	fields, err := decode(row.MessageName, hexBytes(t, row.Protobuf), 0)
	if err != nil {
		t.Fatal(err)
	}
	if scalarAt(fields, 2) != seed.Epoch || !bytes.Equal(bytesAt(fields, 3), seed.Randomness[:]) || row.Digest != s.Alpha {
		t.Fatal("alpha does not bind the resolved epoch source")
	}
	if err := VerifyDispatchVRF(hexBytes(t, doc.VRF.PublicKey), hexBytes(t, s.Alpha), hexBytes(t, s.Proof), hexBytes(t, doc.VRF.Randomness)); err != nil {
		t.Fatal(err)
	}
	for _, height := range []uint64{s.Start, s.Start + s.Length - 1} {
		other, err := ResolveEpochSeed(height, s.Length, s.BeaconHeight, hexBytes(t, s.Beacon), true)
		if err != nil || other != seed {
			t.Fatal("epoch endpoints do not share a source", err)
		}
	}
	for _, invalid := range []struct {
		name                   string
		height, length, beacon uint64
		raw                    []byte
		verified               bool
	}{
		{"epoch zero even with asserted verification", s.Length - 1, s.Length, 0, hexBytes(t, s.Beacon), true},
		{"missing order height", 0, s.Length, s.BeaconHeight, hexBytes(t, s.Beacon), true},
		{"height outside consensus range", math.MaxUint64, s.Length, s.BeaconHeight, hexBytes(t, s.Beacon), true},
		{"zero epoch length", s.Height, 0, s.BeaconHeight, hexBytes(t, s.Beacon), true},
		{"wrong beacon height", s.Height, s.Length, s.BeaconHeight + 1, hexBytes(t, s.Beacon), true},
		{"unverified placeholder", s.Height, s.Length, s.BeaconHeight, hexBytes(t, s.Beacon), false},
		{"missing source", s.Height, s.Length, s.BeaconHeight, nil, true},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if _, err := ResolveEpochSeed(invalid.height, invalid.length, invalid.beacon, invalid.raw, invalid.verified); err == nil {
				t.Fatal("invalid epoch source accepted")
			}
		})
	}
}

func scalarWire(number, value uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(nil, number<<3), value)
}

func TestStreamShapeSeparatesBusinessAndControlCursors(t *testing.T) {
	binding := hexBytes(t, publishedByName(t, "nexus_v1_dispatchstreambindingv1").Protobuf)
	fields, err := decode("nexus.v1.DispatchStreamBindingV1", binding, 0)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytesAt(fields, 6)
	handraise := hexBytes(t, publishedByName(t, "task_v1_standinghandraisev1").Protobuf)
	frame := func(cursor, tag uint64, body, connection []byte) []byte {
		raw := wireBytes(1, connection)
		if cursor != 0 {
			raw = append(raw, scalarWire(2, cursor)...)
		}
		return append(raw, wireBytes(tag, body)...)
	}
	for _, row := range []struct {
		name  string
		raw   []byte
		valid bool
	}{
		{"binding at zero", frame(0, 3, binding, nonce), true},
		{"ack zero means no business receipt", frame(0, 17, nil, nonce), true},
		{"keepalive at zero", frame(0, 18, scalarWire(1, 123), nonce), true},
		{"first business frame", frame(1, 4, handraise, nonce), true},
		{"business cannot use zero", frame(0, 4, handraise, nonce), false},
		{"binding cannot use business cursor", frame(1, 3, binding, nonce), false},
		{"ack cannot use business cursor", frame(1, 17, nil, nonce), false},
		{"keepalive cannot use business cursor", frame(1, 18, nil, nonce), false},
		{"wrong connection nonce", frame(0, 3, binding, bytes.Repeat([]byte{9}, 32)), false},
		{"short nonce", frame(0, 17, nil, nonce[:31]), false},
		{"long nonce", frame(0, 17, nil, append(bytes.Clone(nonce), 1)), false},
		{"missing message", wireBytes(1, nonce), false},
		{"two control messages", append(frame(0, 17, nil, nonce), wireBytes(18, nil)...), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := ValidateMessage("nexus.v1.DispatchStreamFrameV1", row.raw); (err == nil) != row.valid {
				t.Fatalf("stream validity=%v: %v", row.valid, err)
			}
		})
	}
	for _, version := range []byte{0, 2} {
		bad := bytes.Clone(binding)
		if bad[0] != 8 || bad[1] != 1 {
			t.Fatal("fixture schema encoding changed")
		}
		bad[1] = version
		if _, err := SigningDigest("nexus.v1.DispatchStreamBindingV1", bad); err == nil {
			t.Fatal("unsupported unsigned schema version accepted")
		}
	}
}

func TestVerifierHandraiseSharedProofAndPendingAdmissionLeaf(t *testing.T) {
	row := publishedByName(t, "task_v1_verifierhandraisev1")
	key := ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
	opts := ProofKeyOptions{LookupProofKey: func(signer ServiceProofSigner) (ProofKeyBinding, error) {
		if signer != (ServiceProofSigner{ProofParticipantCortex, vectorOperator, 1}) {
			t.Fatal("wrong Verifier proof identity", signer)
		}
		return key, nil
	}}
	raw := hexBytes(t, row.Protobuf)
	if err := VerifyDispatchProof("trueopen-phase1-vector-1", row.MessageName, raw, opts); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDispatchProof("another-chain", row.MessageName, raw, opts); err == nil {
		t.Fatal("Verifier handraise replayed across chains")
	}
	key.ServiceAuthorizationNonce = 2
	if err := VerifyDispatchProof("trueopen-phase1-vector-1", row.MessageName, raw, opts); err == nil {
		t.Fatal("Verifier handraise replayed across generations")
	}
	leaf := publishedByName(t, "handraise_root_leaf_pending_rotation")
	standing := publishedByName(t, "task_v1_standinghandraisev1")
	var standingDigest [32]byte
	copy(standingDigest[:], hexBytes(t, standing.Digest))
	digest, err := HandraiseLeafDigest(standingDigest, false, AdmitRejectServiceKeyRotationPending, 0)
	if err != nil || hex.EncodeToString(digest[:]) != leaf.Digest {
		t.Fatal("pending rejection is not committed", err)
	}
	for _, invalid := range []struct {
		admitted bool
		reason   uint32
		rtt      uint64
	}{{true, 5, 0}, {false, 5, 1}, {false, 6, 0}} {
		if _, err := HandraiseLeafDigest(standingDigest, invalid.admitted, invalid.reason, invalid.rtt); err == nil {
			t.Fatal("invalid pending rejection admitted")
		}
	}
}

func TestBatchResultsLinkRealSignedRecordAcceptAndTakeover(t *testing.T) {
	var doc struct {
		Batches []struct {
			Name          string `json:"name"`
			Record        string `json:"record_vector"`
			Accept        string `json:"accept_vector"`
			DispatchEntry string `json:"dispatch_entry_vector"`
			Takeover      string `json:"takeover_entry_vector"`
			Digest        string `json:"batch_digest_hex"`
			Response      string `json:"response_protobuf_hex"`
			Results       []struct {
				Index      uint32 `json:"item_index"`
				Object     string `json:"object_id_hex"`
				Status     uint32 `json:"status"`
				RejectCode uint32 `json:"reject_code"`
			} `json:"results"`
		} `json:"batch_results"`
	}
	readConsumerFixture(t, &doc)
	if len(doc.Batches) != 3 {
		t.Fatal("missing dispatch batch cases")
	}
	for _, batch := range doc.Batches {
		t.Run(batch.Name, func(t *testing.T) {
			response, err := decode("task.v1.MsgRecordDispatchResponse", hexBytes(t, batch.Response), 0)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(bytesAt(response, 2)) != batch.Digest || len(response[1]) != len(batch.Results) {
				t.Fatal("wire response does not match published results")
			}
			for i, raw := range response[1] {
				item, err := decode("task.v1.BatchItemResultV1", raw.bytes, 1)
				if err != nil {
					t.Fatal(err)
				}
				want := batch.Results[i]
				if scalarAt(item, 1) != uint64(want.Index) || hex.EncodeToString(bytesAt(item, 2)) != want.Object || scalarAt(item, 3) != uint64(want.Status) || scalarAt(item, 4) != uint64(want.RejectCode) {
					t.Fatal("wire per-item response differs")
				}
			}
			record, accept := publishedByName(t, batch.Record), publishedByName(t, batch.Accept)
			proofKey := ProofKeyBinding{PublicKey: hexBytes(t, record.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
			opts := ProofKeyOptions{LookupProofKey: func(ServiceProofSigner) (ProofKeyBinding, error) { return proofKey, nil }}
			for _, source := range []publishedVector{record, accept} {
				if err := VerifyDispatchProof("trueopen-phase1-vector-1", source.MessageName, hexBytes(t, source.Protobuf), opts); err != nil {
					t.Fatal(err)
				}
			}
			fields, err := decode(record.MessageName, hexBytes(t, record.Protobuf), 0)
			if err != nil {
				t.Fatal(err)
			}
			task, err := hashAt(fields, 3)
			if err != nil {
				t.Fatal(err)
			}
			taskHash, err := hashAt(fields, 4)
			if err != nil {
				t.Fatal(err)
			}
			var recordHash, acceptHash [32]byte
			copy(recordHash[:], hexBytes(t, record.Digest))
			copy(acceptHash[:], hexBytes(t, accept.Digest))
			entry := DispatchEntryDigest("trueopen-phase1-vector-1", task, taskHash, recordHash, acceptHash)
			if hex.EncodeToString(entry[:]) != publishedByName(t, batch.DispatchEntry).Digest || batch.Results[0].Object != hex.EncodeToString(entry[:]) {
				t.Fatal("dispatch object_id is not the linked entry digest")
			}
			if batch.Results[1].Object != publishedByName(t, batch.Takeover).Digest {
				t.Fatal("takeover object_id differs from its own domain")
			}
			items := [][]byte{Uint32(uint32(len(batch.Results)))}
			for i, result := range batch.Results {
				if result.Index != uint32(i) {
					t.Fatal("input index order changed")
				}
				if (result.Status == 3) != (result.RejectCode != 0) {
					t.Fatal("rejected result must carry a rejection code and successful results must not")
				}
				items = append(items, FieldFrame(hexBytes(t, result.Object), Uint32(result.Status)))
			}
			digest := HashFields("TRUEOPEN_BATCH_RESULT_V1", []byte("trueopen-phase1-vector-1"), []byte("DISPATCH_RECORD"), Uint32(uint32(len(batch.Results))), FieldFrame(items...))
			if hex.EncodeToString(digest[:]) != batch.Digest {
				t.Fatal("dispatch batch digest differs from actual per-item results")
			}
		})
	}
}

func TestRetiredPoolCommitmentIsAbsent(t *testing.T) {
	var doc struct {
		Order map[string]json.RawMessage `json:"weighted_order"`
	}
	readConsumerFixture(t, &doc)
	if _, exists := doc.Order["pool_hash"]; exists {
		t.Fatal("retired dispatch pool commitment reappeared")
	}
}
