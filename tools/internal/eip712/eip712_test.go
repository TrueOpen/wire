package eip712

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestKeccak256KnownAnswers(t *testing.T) {
	cases := map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
	}
	for input, want := range cases {
		got := Keccak256([]byte(input))
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("keccak256(%q) = %x, want %s", input, got, want)
		}
	}
	// A message longer than one 136-byte block, split across chunks.
	long := bytes.Repeat([]byte{'a'}, 200)
	whole := Keccak256(long)
	split := Keccak256(long[:7], long[7:150], long[150:])
	if whole != split {
		t.Fatal("chunked input hashes differently")
	}
}

// Private key 1 is the generator itself; its address is well known.
func TestKeyOneAddress(t *testing.T) {
	key, err := ParseKey("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if got := ChecksumAddress(key.Address()); got != "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" {
		t.Fatalf("address of key 1 is %s", got)
	}
}

func TestSignRecoverRoundTripAndCanonicalForm(t *testing.T) {
	key, _ := ParseKey("0303030303030303030303030303030303030303030303030303030303030303")
	for i := 0; i < 16; i++ {
		digest := Keccak256([]byte{byte(i)})
		signature := key.Sign(digest)
		if !bytes.Equal(signature, key.Sign(digest)) {
			t.Fatal("signing is not deterministic")
		}
		address, err := Recover(digest, signature)
		if err != nil || address != key.Address() {
			t.Fatalf("round trip %d: %v", i, err)
		}
		high := append([]byte(nil), signature...)
		s := new(big.Int).SetBytes(high[32:64])
		s.Sub(orderN, s).FillBytes(high[32:64])
		high[64] ^= 1
		if _, err := Recover(digest, high); err == nil {
			t.Fatal("high-S signature accepted")
		}
		flipped := append([]byte(nil), signature...)
		flipped[64] -= 27
		if _, err := Recover(digest, flipped); err == nil {
			t.Fatal("V in {0, 1} accepted")
		}
		if _, err := Recover(digest, signature[:64]); err == nil {
			t.Fatal("64-byte signature accepted")
		}
	}
}

// The vectors below were produced by Node before this package existed. They
// pin the encoder, the digest and RFC 6979 to an implementation outside wire.
func TestReproducesPublishedAccountSigningVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "v1", "shared", "account_signing_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	account := doc["account"].(map[string]any)
	key, err := ParseKey(account["private_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	address := key.Address()
	if hex.EncodeToString(address[:]) != account["address_bytes"] || ChecksumAddress(address) != account["address_0x"] ||
		hex.EncodeToString(key.PublicCompressed()) != account["pub_compressed"] ||
		hex.EncodeToString(key.PublicXY()) != account["pub_uncompressed_xy"] {
		t.Fatal("account key derivation differs from the published account")
	}

	order := doc["task_order"].(map[string]any)
	domain := order["domain"].(map[string]any)
	d := Domain{Name: domain["name"].(string), Version: domain["version"].(string), ChainID: domain["chain_id"].(string)}
	separator, err := d.Separator()
	if err != nil || hex.EncodeToString(separator[:]) != domain["domain_separator"] {
		t.Fatalf("order domain separator %x", separator)
	}
	primary, types, err := ParseEncodeType(order["encode_type"].(string))
	if err != nil {
		t.Fatal(err)
	}
	typeHash := types.TypeHash(primary)
	if hex.EncodeToString(typeHash[:]) != order["type_hash"] {
		t.Fatal("order type hash")
	}
	hashStruct, err := types.HashStruct(primary, order["message"].(map[string]any))
	if err != nil || hex.EncodeToString(hashStruct[:]) != order["hash_struct"] {
		t.Fatalf("order hash_struct %x: %v", hashStruct, err)
	}
	digest := SigningDigest(separator, hashStruct)
	if hex.EncodeToString(digest[:]) != order["signing_digest"] {
		t.Fatal("order signing digest")
	}
	if hex.EncodeToString(key.Sign(digest)) != order["signature_65"] {
		t.Fatal("RFC 6979 signature differs from the published order signature")
	}
}
