package dispatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestPublishedOutputStreamHeaderSignature(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "output_stream_header_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Fields    []projectionField `json:"fields"`
			Domain    string            `json:"domain"`
			Digest    string            `json:"digest_hex"`
			Preimage  string            `json:"preimage_hex"`
			Size      int               `json:"preimage_size_bytes"`
			Key       string            `json:"service_pubkey_compressed_hex"`
			Signature string            `json:"signature_raw64_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) != 1 {
		t.Fatal("missing stream-header signature vector")
	}
	for _, row := range doc.Vectors {
		get := func(name string) projectionField { return selectedField(t, row.Fields, name) }
		chain := []byte(get("chain_id").UTF8)
		task := hexBytes(t, get("task_hash").Hex)
		ticket := hexBytes(t, get("dispatch_ticket_hash").Hex)
		instance := Uint32(uint32(fieldUint(t, get("stream_instance"))))
		recipient := hexBytes(t, get("user_recipient_pubkey").Hex)
		outputKey := hexBytes(t, get("output_key_commitment").Hex)
		keyPackage := hexBytes(t, get("key_package_hash").Hex)
		preimage := FieldFrame([]byte(row.Domain), chain, task, ticket, instance, recipient, outputKey, keyPackage)
		if !bytes.Equal(preimage, hexBytes(t, row.Preimage)) || len(preimage) != row.Size {
			t.Fatal("stream-header preimage or size is stale")
		}
		digest := sha256.Sum256(preimage)
		if !bytes.Equal(digest[:], hexBytes(t, row.Digest)) {
			t.Fatal("stream-header digest is stale")
		}
		key, signature := hexBytes(t, row.Key), hexBytes(t, row.Signature)
		if err := VerifyDigestSignature(key, digest[:], signature); err != nil {
			t.Fatal("stream-header raw64 signature is stale", err)
		}
		legacy := HashFields(row.Domain, chain, task, Uint32(0), instance, recipient, outputKey, keyPackage)
		if VerifyDigestSignature(key, legacy[:], signature) == nil {
			t.Fatal("signature still authenticates the retired attempt-zero projection")
		}
		ticket[0] ^= 1
		other := HashFields(row.Domain, chain, task, ticket, instance, recipient, outputKey, keyPackage)
		if VerifyDigestSignature(key, other[:], signature) == nil {
			t.Fatal("signature does not bind its dispatch ticket")
		}
	}
}

func array32(t *testing.T, value string) (out [32]byte) {
	t.Helper()
	raw := hexBytes(t, value)
	if len(raw) != 32 {
		t.Fatal("expected raw32 fixture value")
	}
	copy(out[:], raw)
	return
}

func TestOutputFramesCannotCrossDispatchAttempts(t *testing.T) {
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	pub := key.PubKey().SerializeCompressed()
	task := array32(t, hex.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	var ticketA, ticketB, rootA, rootB [32]byte
	ticketA[0] = 1
	ticketB[0] = 2
	rootA[0] = 3
	rootB[0] = 4
	a := OutputChunkDigest("chain", task, ticketA, 0, rootA)
	b := OutputChunkDigest("chain", task, ticketB, 0, rootB)
	old := SignDigest(key, a)
	if err := VerifyDigestSignature(pub, a[:], old); err != nil {
		t.Fatal(err)
	}
	// The accepted receipt points to B; reconstructing its signing scope must
	// reject a genuine frame from A, even for the same order, Worker and seq.
	witness := OutputChunkDigest("chain", task, ticketB, 0, rootA)
	if VerifyDigestSignature(pub, witness[:], old) == nil {
		t.Fatal("old attempt can falsely incriminate the accepted attempt")
	}
	if err := VerifyDigestSignature(pub, b[:], SignDigest(key, b)); err != nil {
		t.Fatal(err)
	}
	finA, err := OutputFinDigest("chain", task, ticketA, 0, rootA, 1)
	if err != nil {
		t.Fatal(err)
	}
	finB, err := OutputFinDigest("chain", task, ticketB, 0, rootA, 1)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyDigestSignature(pub, finB[:], SignDigest(key, finA)) == nil {
		t.Fatal("Fin crossed dispatch attempts")
	}
	for _, reason := range []uint32{0, 7, ^uint32(0)} {
		if _, err := OutputFinDigest("chain", task, ticketA, 0, rootA, reason); err == nil {
			t.Fatal("invalid Fin reason admitted")
		}
	}
}

func TestPublishedAttemptBoundOutputVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "output_mmr_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		MMR struct {
			Chain string `json:"chain_id"`
			Task  string `json:"task_hash_hex"`
		} `json:"mmr"`
		Chunk struct {
			Ticket string `json:"dispatch_ticket_hash_hex"`
			Key    string `json:"test_public_key_compressed_hex"`
			Cases  []struct {
				Seq       uint64 `json:"seq"`
				Root      string `json:"mmr_root_hex"`
				Digest    string `json:"digest_hex"`
				Signature string `json:"signature_hex"`
			} `json:"cases"`
		} `json:"chunk_signing"`
		Fin struct {
			Chain     string `json:"chain_id"`
			Task      string `json:"task_hash_hex"`
			Ticket    string `json:"dispatch_ticket_hash_hex"`
			Seq       uint64 `json:"final_seq"`
			Root      string `json:"output_mmr_root_hex"`
			Signature string `json:"eos_token_signature_hex"`
			Cases     []struct {
				Reason uint32 `json:"value"`
				Digest string `json:"digest_hex"`
			} `json:"accepted_finish_reasons"`
		} `json:"fin_signing"`
	}
	if err = json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	for _, row := range d.Chunk.Cases {
		digest := OutputChunkDigest(d.MMR.Chain, array32(t, d.MMR.Task), array32(t, d.Chunk.Ticket), row.Seq, array32(t, row.Root))
		if hex.EncodeToString(digest[:]) != row.Digest {
			t.Fatal("chunk differs from independent projection")
		}
		if err = VerifyDigestSignature(hexBytes(t, d.Chunk.Key), digest[:], hexBytes(t, row.Signature)); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range d.Fin.Cases {
		digest, err := OutputFinDigest(d.Fin.Chain, array32(t, d.Fin.Task), array32(t, d.Fin.Ticket), d.Fin.Seq, array32(t, d.Fin.Root), row.Reason)
		if err != nil || hex.EncodeToString(digest[:]) != row.Digest {
			t.Fatal("Fin differs from independent projection", err)
		}
		if row.Reason == 1 {
			if err = VerifyDigestSignature(hexBytes(t, d.Chunk.Key), digest[:], hexBytes(t, d.Fin.Signature)); err != nil {
				t.Fatal(err)
			}
		}
	}
}
