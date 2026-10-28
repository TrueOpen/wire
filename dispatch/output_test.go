package dispatch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

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
