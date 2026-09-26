package bus

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

func TestOutputStreamHeaderV2SigningVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "task", "output_stream_header_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Domain            string `json:"domain"`
			DigestHex         string `json:"digest_hex"`
			SignatureRaw64Hex string `json:"signature_raw64_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) != 1 {
		t.Fatalf("header vector count %d", len(doc.Vectors))
	}
	vector := doc.Vectors[0]
	preimage := frame(
		[]byte(vector.Domain),
		[]byte("trueopen-golden-1"),
		bytes.Repeat([]byte{0x22}, 32),
		u32be(0), u32be(1), nil,
		make([]byte, 32), make([]byte, 32),
	)
	digest := sha256.Sum256(preimage)
	if hex.EncodeToString(digest[:]) != vector.DigestHex {
		t.Fatal("OutputStreamHeaderV2 signing digest does not match its frozen field projection")
	}
	key := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x01}, 32))
	signature := SignDigest(key, digest)
	if hex.EncodeToString(signature) != vector.SignatureRaw64Hex {
		t.Fatalf("header signature %x, want %s", signature, vector.SignatureRaw64Hex)
	}
}
