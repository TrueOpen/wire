package dispatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func encodeTestMessage(name string, fields decoded) []byte {
	numbers := make([]int, 0, len(fields))
	for number := range fields {
		numbers = append(numbers, int(number))
	}
	sort.Ints(numbers)
	var raw []byte
	for _, n := range numbers {
		for _, v := range fields[uint32(n)] {
			if protoTables[name][uint32(n)].kind == kindVarint {
				raw = append(raw, scalarWire(uint64(n), v.varint)...)
			} else {
				raw = append(raw, wireBytes(uint64(n), v.bytes)...)
			}
		}
	}
	return raw
}

func readSyncFixture(t *testing.T) (string, string, string, []struct {
	publishedVector
	Equivalent string `json:"equivalent_protobuf_hex"`
}) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "builder_sync_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Chain    string `json:"chain_id"`
		Sender   string `json:"sender_operator_address"`
		Receiver string `json:"receiver_operator_address"`
		Vectors  []struct {
			publishedVector
			Equivalent string `json:"equivalent_protobuf_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Chain, doc.Sender, doc.Receiver, doc.Vectors
}

func TestBuilderSyncVectorsSurviveReserializationAndUseCurrentLiveAuthority(t *testing.T) {
	chain, sender, receiver, vectors := readSyncFixture(t)
	for _, row := range vectors {
		t.Run(row.Name, func(t *testing.T) {
			current := ProofKeyBinding{PublicKey: hexBytes(t, row.PublicKey), ServiceAuthorizationNonce: 1, Status: ProofKeyActive}
			opts := ProofKeyOptions{LookupProofKey: func(signer ServiceProofSigner) (ProofKeyBinding, error) {
				if signer.ParticipantType != ProofParticipantBuilder || signer.OperatorAddress != sender || signer.ServiceAuthorizationNonce != 0 {
					t.Fatal("sync did not select the current stable Builder identity", signer)
				}
				return current, nil
			}}
			for _, encoded := range []string{row.Protobuf, row.Equivalent} {
				raw := hexBytes(t, encoded)
				got, err := SigningDigest(row.MessageName, raw)
				if err != nil || hex.EncodeToString(got[:]) != row.Digest {
					t.Fatal("serialization changed the independently computed digest", err)
				}
				if err := VerifyBuilderSyncRequest(chain, receiver, raw, opts); err != nil {
					t.Fatal(err)
				}
				if VerifyBuilderSyncRequest(chain+"-other", receiver, raw, opts) == nil || VerifyBuilderSyncRequest(chain, account(t, 9), raw, opts) == nil {
					t.Fatal("sync was replayable on another chain or receiver")
				}
			}
			current.Status = ProofKeyRevoked
			if err := VerifyBuilderSyncRequest(chain, receiver, hexBytes(t, row.Protobuf), opts); !errors.Is(err, ErrProofKeyUnavailable) {
				t.Fatal("revoked identity authorized a live sync", err)
			}
			current = ProofKeyBinding{PublicKey: secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32)).PubKey().SerializeCompressed(), ServiceAuthorizationNonce: 2, Status: ProofKeyActive}
			if VerifyBuilderSyncRequest(chain, receiver, hexBytes(t, row.Protobuf), opts) == nil {
				t.Fatal("retired service signature verified against the replacement")
			}
			request, err := decode("nexus.v1.SyncRequest", hexBytes(t, row.Protobuf), 0)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := SigningDigest("nexus.v1.SyncRequest", hexBytes(t, row.Protobuf))
			if err != nil {
				t.Fatal(err)
			}
			request[2] = []value{{bytes: SignDigest(secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32)), digest)}}
			if err := VerifyBuilderSyncRequest(chain, receiver, encodeTestMessage("nexus.v1.SyncRequest", request), opts); err != nil {
				t.Fatal("new current key could not authenticate retransmission of the same batch", err)
			}
		})
	}
}

func TestBuilderSyncRejectsMalformedBatchesBeforeSignatureVerification(t *testing.T) {
	row := publishedByName(t, "builder_sync_full_batch")
	for _, test := range []struct {
		name   string
		change func(decoded)
	}{
		{"wrong schema", func(batch decoded) { batch[1] = []value{{varint: 2}} }},
		{"same receiver", func(batch decoded) { batch[4] = batch[3] }},
		{"wrong Session scope", func(batch decoded) { batch[5] = []value{{bytes: bytes.Repeat([]byte{9}, 32)}} }},
		{"wrong BuilderSet scope", func(batch decoded) { batch[8] = []value{{bytes: bytes.Repeat([]byte{9}, 32)}} }},
		{"no items or output", func(batch decoded) { delete(batch, 9); delete(batch, 10) }},
		{"too many items", func(batch decoded) {
			first, _ := decode("nexus.v1.BuilderSyncItemV1", batch[9][0].bytes, 0)
			batch[9] = make([]value, MaxBuilderSyncEntries+1)
			for i := range batch[9] {
				first[1] = []value{{varint: uint64(i + 1)}}
				batch[9][i] = value{bytes: encodeTestMessage("nexus.v1.BuilderSyncItemV1", first)}
			}
		}},
		{"zero item sequence", func(batch decoded) {
			item, _ := decode("nexus.v1.BuilderSyncItemV1", batch[9][0].bytes, 0)
			item[1] = []value{{varint: 0}}
			batch[9][0].bytes = encodeTestMessage("nexus.v1.BuilderSyncItemV1", item)
		}},
		{"gap", func(batch decoded) {
			item, _ := decode("nexus.v1.BuilderSyncItemV1", batch[9][1].bytes, 0)
			item[1] = []value{{varint: 99}}
			batch[9][1].bytes = encodeTestMessage("nexus.v1.BuilderSyncItemV1", item)
		}},
		{"missing oneof", func(batch decoded) { batch[9][0].bytes = scalarWire(1, 1) }},
		{"duplicate oneof", func(batch decoded) { batch[9][0].bytes = append(batch[9][0].bytes, wireBytes(5, nil)...) }},
		{"unknown oneof", func(batch decoded) { batch[9][0].bytes = append(scalarWire(1, 1), wireBytes(7, nil)...) }},
		{"output ticket mismatch", func(batch decoded) {
			out, _ := decode("nexus.v1.BuilderSyncOutputV1", bytesAt(batch, 10), 0)
			out[1] = []value{{bytes: bytes.Repeat([]byte{3}, 32)}}
			batch[10] = []value{{bytes: encodeTestMessage("nexus.v1.BuilderSyncOutputV1", out)}}
		}},
		{"output gap", func(batch decoded) {
			out, _ := decode("nexus.v1.BuilderSyncOutputV1", bytesAt(batch, 10), 0)
			chunk, _ := decode("nexus.v1.OutputChunkV1", out[4][1].bytes, 0)
			chunk[1] = []value{{varint: 99}}
			out[4][1].bytes = encodeTestMessage("nexus.v1.OutputChunkV1", chunk)
			batch[10] = []value{{bytes: encodeTestMessage("nexus.v1.BuilderSyncOutputV1", out)}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := decode("nexus.v1.SyncRequest", hexBytes(t, row.Protobuf), 0)
			if err != nil {
				t.Fatal(err)
			}
			batch, err := decode("nexus.v1.BuilderSyncBatchV1", bytesAt(request, 1), 0)
			if err != nil {
				t.Fatal(err)
			}
			test.change(batch)
			request[1] = []value{{bytes: encodeTestMessage("nexus.v1.BuilderSyncBatchV1", batch)}}
			if _, err := SigningDigest("nexus.v1.SyncRequest", encodeTestMessage("nexus.v1.SyncRequest", request)); err == nil {
				t.Fatal("malformed batch reached signature projection")
			}
		})
	}
}

func syncItems(t *testing.T, encoded string) [][]byte {
	t.Helper()
	request, err := decode("nexus.v1.SyncRequest", hexBytes(t, encoded), 0)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := decode("nexus.v1.BuilderSyncBatchV1", bytesAt(request, 1), 1)
	if err != nil {
		t.Fatal(err)
	}
	items := make([][]byte, 0, len(batch[9]))
	for _, item := range batch[9] {
		items = append(items, item.bytes)
	}
	return items
}

// The duplicate-item comparison must be the per-item projection the batch
// signature commits to. The published preimages were computed independently,
// so every item's bytes must reassemble the signed REPEATED_V1 items field.
func TestBuilderSyncItemCanonicalBytesMatchSignedBatchProjection(t *testing.T) {
	_, _, _, vectors := readSyncFixture(t)
	covered := 0
	for _, row := range vectors {
		items, equivalent := syncItems(t, row.Protobuf), syncItems(t, row.Equivalent)
		if len(items) == 0 {
			continue
		}
		if len(equivalent) != len(items) {
			t.Fatal(row.Name, "equivalent encoding changed the item count")
		}
		parts := [][]byte{Uint32(uint32(len(items)))}
		for i, raw := range items {
			got, err := BuilderSyncItemCanonicalBytes(raw)
			if err != nil {
				t.Fatal(row.Name, err)
			}
			again, err := BuilderSyncItemCanonicalBytes(equivalent[i])
			if err != nil || !bytes.Equal(got, again) {
				t.Fatal(row.Name, "reordered fields or explicit defaults changed an item's identity", err)
			}
			parts = append(parts, got)
			covered++
		}
		if !bytes.Contains(hexBytes(t, row.Preimage), FieldFrame(FieldFrame(parts...))) {
			t.Fatal(row.Name, "item projections differ from the signed batch items field")
		}
	}
	if covered == 0 {
		t.Fatal("no published sync item was compared")
	}

	conflicted := false
	for _, raw := range syncItems(t, publishedByName(t, "builder_sync_full_batch").Protobuf) {
		item, err := decode("nexus.v1.BuilderSyncItemV1", raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(item[3]) == 0 {
			continue
		}
		chunk, err := decode("nexus.v1.BuilderSyncInputChunkV1", bytesAt(item, 3), 0)
		if err != nil {
			t.Fatal(err)
		}
		chunk[4] = []value{{bytes: []byte("application/x-conflict")}}
		item[3] = []value{{bytes: encodeTestMessage("nexus.v1.BuilderSyncInputChunkV1", chunk)}}
		original, err := BuilderSyncItemCanonicalBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := BuilderSyncItemCanonicalBytes(encodeTestMessage("nexus.v1.BuilderSyncItemV1", item))
		if err != nil || bytes.Equal(original, changed) {
			t.Fatal("a conflicting payload at the same sequence compared equal", err)
		}
		if _, err := BuilderSyncItemCanonicalBytes(append(append([]byte{}, raw...), wireBytes(5, nil)...)); err == nil {
			t.Fatal("a duplicate oneof item produced comparison bytes")
		}
		conflicted = true
		break
	}
	if !conflicted {
		t.Fatal("full batch has no input chunk item to mutate")
	}
}

func TestCanonicalOneofIncludesProtoTagAndPayloadFrame(t *testing.T) {
	const name = "test.OneofProjection"
	protoTables[name] = messageSpec{2: {name: "first", kind: kindBytes, oneof: 1}, 3: {name: "second", kind: kindBytes, oneof: 1}}
	defer delete(protoTables, name)
	for _, number := range []uint32{2, 3} {
		parts, err := canonicalFields(name, wireBytes(uint64(number), []byte("same")), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		want := append(binary.BigEndian.AppendUint32(nil, number), FieldFrame([]byte("same"))...)
		if len(parts) != 1 || !bytes.Equal(parts[0], want) {
			t.Fatal("oneof omitted its proto tag or payload frame")
		}
	}
}

func TestDispatchInputChunksAssembleWholeInputFromZero(t *testing.T) {
	var joined []byte
	var expected []byte
	var total uint64
	count := uint64(0)
	for index, name := range []string{"nexus_v1_dispatchinputresponsev1", "nexus_v1_dispatchinputresponsev1_chunk_1", "nexus_v1_dispatchinputresponsev1_chunk_2"} {
		row := publishedByName(t, name)
		fields, err := decode(row.MessageName, hexBytes(t, row.Protobuf), 0)
		if err != nil {
			t.Fatal(err)
		}
		if scalarAt(fields, 6) != uint64(index) || scalarAt(fields, 7) != 3 {
			t.Fatal("published input chunks are not zero-based")
		}
		if index == 0 {
			expected = bytesAt(fields, 3)
			total = scalarAt(fields, 4)
		} else if !bytes.Equal(expected, bytesAt(fields, 3)) || total != scalarAt(fields, 4) {
			t.Fatal("whole-input facts changed between chunks")
		}
		joined = append(joined, bytesAt(fields, 5)...)
		count++
		for _, change := range []func(decoded){func(f decoded) { f[6] = []value{{varint: 3}} }, func(f decoded) { f[7] = []value{{varint: 0}} }, func(f decoded) { f[4] = []value{{varint: 1}} }} {
			mutated, _ := decode(row.MessageName, hexBytes(t, row.Protobuf), 0)
			change(mutated)
			if ValidateMessage(row.MessageName, encodeTestMessage(row.MessageName, mutated)) == nil {
				t.Fatal("invalid chunk base/count/size was accepted")
			}
		}
	}
	sum := sha256.Sum256(joined)
	if count != 3 || uint64(len(joined)) != total || !bytes.Equal(sum[:], expected) {
		t.Fatal("chunk vectors do not reconstruct their committed whole input")
	}
}
