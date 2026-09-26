package bus

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// bindingVectorFile mirrors testdata/v1/bus/nats_user_binding_v1_vectors.json.
// The first case is the minimum vector frozen in,
// whose preimage and digest were derived independently of this package (a
// standalone Go program over raw framing, re-checked with xxd | sha256sum);
// this test is the implementation leg of that cross-check.
type bindingVectorFile struct {
	Domain              string `json:"domain"`
	PrivateKey          string `json:"private_key"`
	PublicKeyCompressed string `json:"public_key_compressed"`
	NATSUserPubkey      string `json:"nats_user_pubkey"`
	Cases               []struct {
		Name   string `json:"name"`
		Fields struct {
			SchemaVersion             uint32 `json:"schema_version"`
			ChainID                   string `json:"chain_id"`
			ParticipantType           int32  `json:"participant_type"`
			OperatorAddress           string `json:"operator_address"`
			ServiceAuthorizationNonce string `json:"service_authorization_nonce"`
			NATSUserPubkey            string `json:"nats_user_pubkey"`
			IssuedAtUnixMS            string `json:"issued_at_unix_ms"`
		} `json:"fields"`
		OperatorCodecBytes string `json:"operator_codec_bytes"`
		Expected           struct {
			SigningPreimage string `json:"signing_preimage"`
			SigningDigest   string `json:"signing_digest"`
			Signature       string `json:"signature"`
			BindingBytes    string `json:"binding_bytes"`
			Token           string `json:"token"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadBindingVectors(t *testing.T) bindingVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "v1", "bus", "nats_user_binding_v1_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file bindingVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.Domain != BindingDomain {
		t.Fatalf("vector domain %q != implementation domain %q", file.Domain, BindingDomain)
	}
	if len(file.Cases) == 0 {
		t.Fatal("vector file has no cases")
	}
	return file
}

func bindingVectorFields(t *testing.T, file bindingVectorFile, index int) BindingFields {
	t.Helper()
	c := file.Cases[index]
	return BindingFields{
		SchemaVersion:             c.Fields.SchemaVersion,
		ChainID:                   c.Fields.ChainID,
		ParticipantType:           c.Fields.ParticipantType,
		OperatorAddress:           c.Fields.OperatorAddress,
		ServiceAuthorizationNonce: mustU64(t, c.Fields.ServiceAuthorizationNonce),
		NATSUserPubkey:            c.Fields.NATSUserPubkey,
		IssuedAtUnixMS:            mustU64(t, c.Fields.IssuedAtUnixMS),
	}
}

// TestBindingMinimumVectorIsFrozen pins this contract values literally, so the
// fixture file cannot be regenerated away from the contract without this test
// noticing.
func TestBindingMinimumVectorIsFrozen(t *testing.T) {
	file := loadBindingVectors(t)
	c := file.Cases[0]
	const (
		wantDigest    = "114c75653efeb0b8f316f8078bd4a50abb3f7c018716cbd5adf08e3ceb4ce917"
		wantSignature = "3d84823f77ee958f4368487a98af3ba459044c81ced3efaf6029a08005d862796ceef1faf13085e7e78eac2a311f0e3e388c84dab8ccfe7567de246f323d2c24"
		wantPubkey    = "UA5WUJ54Z23KILLCUOUNAKTPBVZWKMQVO4O6EQ5GHLAERIMLLHNCTYM5"
	)
	if c.Fields.ChainID != "c" || c.Fields.ServiceAuthorizationNonce != "1" || c.Fields.IssuedAtUnixMS != "1" ||
		c.Fields.OperatorAddress != "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man" || c.Fields.NATSUserPubkey != wantPubkey {
		t.Fatalf("case 0 inputs drifted from this contract: %+v", c.Fields)
	}
	if c.Expected.SigningDigest != wantDigest {
		t.Fatalf("case 0 digest drifted from this contract: %s", c.Expected.SigningDigest)
	}
	if c.Expected.Signature != wantSignature {
		t.Fatalf("case 0 signature drifted from this contract: %s", c.Expected.Signature)
	}
}

func TestBindingVectorsCrossCheck(t *testing.T) {
	file := loadBindingVectors(t)
	privKey := secp256k1.PrivKeyFromBytes(mustHex(t, file.PrivateKey))
	pubKey := privKey.PubKey().SerializeCompressed()
	if hex.EncodeToString(pubKey) != file.PublicKeyCompressed {
		t.Fatalf("public key mismatch: %x", pubKey)
	}
	if err := ValidateNATSUserPublicKey(file.NATSUserPubkey); err != nil {
		t.Fatalf("fixture nats_user_pubkey rejected: %v", err)
	}
	for i, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			fields := bindingVectorFields(t, file, i)

			codec, err := OperatorAddressCodecBytes(fields.OperatorAddress)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(codec) != c.OperatorCodecBytes {
				t.Fatalf("operator codec bytes mismatch: %x", codec)
			}
			preimage, err := BindingSigningPreimage(fields)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(preimage) != c.Expected.SigningPreimage {
				t.Fatalf("preimage mismatch\n got %x", preimage)
			}
			digest, err := BindingSigningDigest(fields)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(digest[:]) != c.Expected.SigningDigest {
				t.Fatalf("signing digest mismatch: %x", digest)
			}
			signature := SignDigest(privKey, digest)
			if hex.EncodeToString(signature) != c.Expected.Signature {
				t.Fatalf("signature mismatch\n got %x\nwant %s", signature, c.Expected.Signature)
			}
			if err := VerifyBindingSignature(fields, signature, pubKey); err != nil {
				t.Fatalf("verify: %v", err)
			}

			encoded, err := EncodeBinding(fields, signature)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(encoded) != c.Expected.BindingBytes {
				t.Fatalf("binding bytes mismatch\n got %x", encoded)
			}
			token := EncodeBindingToken(encoded)
			if token != c.Expected.Token {
				t.Fatalf("token mismatch\n got %s", token)
			}
			raw, err := DecodeBindingToken(token)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeBinding(raw)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Fields != fields {
				t.Fatalf("decoded fields differ\n got %+v\nwant %+v", decoded.Fields, fields)
			}
			if hex.EncodeToString(decoded.Signature) != c.Expected.Signature || decoded.RawSize != len(encoded) {
				t.Fatalf("decoded signature or size differ")
			}
		})
	}
}

// TestBindingFieldMutations flips every projection field and asserts the digest
// moves, so no field can be silently dropped from the preimage.
func TestBindingFieldMutations(t *testing.T) {
	file := loadBindingVectors(t)
	base := bindingVectorFields(t, file, 0)
	baseDigest, err := BindingSigningDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	// A second well-formed user key for the pubkey mutation: the fixture key
	// with its 32 key bytes flipped and the CRC recomputed.
	otherPubkey := recomputeNATSUserPubkey(t, base.NATSUserPubkey, func(key []byte) { key[0] ^= 0x01 })
	mutations := map[string]func(BindingFields) BindingFields{
		"chain_id": func(f BindingFields) BindingFields { f.ChainID += "x"; return f },
		"operator_address": func(f BindingFields) BindingFields {
			f.OperatorAddress = "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut"
			return f
		},
		"service_authorization_nonce": func(f BindingFields) BindingFields { f.ServiceAuthorizationNonce++; return f },
		"nats_user_pubkey":            func(f BindingFields) BindingFields { f.NATSUserPubkey = otherPubkey; return f },
		"issued_at_unix_ms":           func(f BindingFields) BindingFields { f.IssuedAtUnixMS++; return f },
	}
	for name, mutate := range mutations {
		digest, err := BindingSigningDigest(mutate(base))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest == baseDigest {
			t.Fatalf("%s: digest did not change", name)
		}
	}
	// schema_version and participant_type are closed sets: the only other
	// values are rejected outright rather than producing a different digest.
	for name, mutate := range map[string]func(BindingFields) BindingFields{
		"schema_version":   func(f BindingFields) BindingFields { f.SchemaVersion = 2; return f },
		"participant_type": func(f BindingFields) BindingFields { f.ParticipantType = ParticipantBuilder; return f },
	} {
		if _, err := BindingSigningDigest(mutate(base)); !errors.Is(err, ErrBinding) {
			t.Fatalf("%s: want ErrBinding, got %v", name, err)
		}
	}
}

func TestBindingRejectsUnencodableInputs(t *testing.T) {
	file := loadBindingVectors(t)
	base := bindingVectorFields(t, file, 0)
	cases := map[string]func(BindingFields) BindingFields{
		"empty chain_id":          func(f BindingFields) BindingFields { f.ChainID = ""; return f },
		"invalid utf8 chain_id":   func(f BindingFields) BindingFields { f.ChainID = "\xff"; return f },
		"unspecified participant": func(f BindingFields) BindingFields { f.ParticipantType = 0; return f },
		"uppercase address":       func(f BindingFields) BindingFields { f.OperatorAddress = strings.ToUpper(f.OperatorAddress); return f },
		"foreign hrp address": func(f BindingFields) BindingFields {
			f.OperatorAddress = "cosmos1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdcyqpvac"
			return f
		},
		"empty pubkey": func(f BindingFields) BindingFields { f.NATSUserPubkey = ""; return f },
		"seed instead of pubkey": func(f BindingFields) BindingFields {
			f.NATSUserPubkey = "SUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEQ"
			return f
		},
		"pubkey bad checksum": func(f BindingFields) BindingFields { f.NATSUserPubkey = flipLastChar(f.NATSUserPubkey); return f },
		"lowercase pubkey":    func(f BindingFields) BindingFields { f.NATSUserPubkey = strings.ToLower(f.NATSUserPubkey); return f },
	}
	for name, mutate := range cases {
		if _, err := BindingSigningPreimage(mutate(base)); !errors.Is(err, ErrBinding) {
			t.Fatalf("%s: want ErrBinding, got %v", name, err)
		}
	}
}

func TestBindingTokenRejections(t *testing.T) {
	file := loadBindingVectors(t)
	token := file.Cases[0].Expected.Token
	body := token[len(BindingTokenPrefix):]
	cases := map[string]string{
		"missing prefix": body,
		"wrong prefix":   "trueopen-nub2." + body,
		"padded base64":  token + "==",
		"not base64url":  BindingTokenPrefix + "!!!",
		"empty body":     BindingTokenPrefix,
		"oversized":      BindingTokenPrefix + strings.Repeat("A", 4*(MaxBindingBytes/3)+8),
	}
	for name, bad := range cases {
		if _, err := DecodeBindingToken(bad); !errors.Is(err, ErrBinding) {
			t.Fatalf("%s: want ErrBinding, got %v", name, err)
		}
	}
}

func TestDecodeBindingRejections(t *testing.T) {
	file := loadBindingVectors(t)
	good := mustHex(t, file.Cases[0].Expected.BindingBytes)
	if _, err := DecodeBinding(good); err != nil {
		t.Fatalf("golden bytes rejected: %v", err)
	}
	cases := map[string][]byte{
		"empty":               nil,
		"unknown field 9":     append(append([]byte{}, good...), encodeBytesField(9, []byte{1})...),
		"duplicate chain_id":  append(append([]byte{}, good...), encodeBytesField(2, []byte("c"))...),
		"wrong wire type":     append(append([]byte{}, good...), 0x0a, 0x00),
		"short signature":     mustBindingWithSignature(t, file, make([]byte, 63)),
		"builder participant": replaceByte(good, 0x18, 0x01, 0x18, 0x02),
		"oversized":           append(append([]byte{}, good...), encodeBytesField(2, make([]byte, MaxBindingBytes))...),
	}
	for name, bad := range cases {
		if _, err := DecodeBinding(bad); !errors.Is(err, ErrBinding) {
			t.Fatalf("%s: want ErrBinding, got %v", name, err)
		}
	}
}

func TestVerifyBindingSignatureRejectsWrongKeyAndTamperedField(t *testing.T) {
	file := loadBindingVectors(t)
	fields := bindingVectorFields(t, file, 0)
	signature := mustHex(t, file.Cases[0].Expected.Signature)
	pubKey := mustHex(t, file.PublicKeyCompressed)
	if err := VerifyBindingSignature(fields, signature, pubKey); err != nil {
		t.Fatal(err)
	}
	other := secp256k1.PrivKeyFromBytes(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000002"))
	if err := VerifyBindingSignature(fields, signature, other.PubKey().SerializeCompressed()); err == nil {
		t.Fatal("signature verified under a different service key")
	}
	tampered := fields
	tampered.ServiceAuthorizationNonce++
	if err := VerifyBindingSignature(tampered, signature, pubKey); err == nil {
		t.Fatal("signature verified after the nonce changed")
	}
	highS := append([]byte{}, signature...)
	// Force high-S by negating s mod n: s' = n - s.
	var s secp256k1.ModNScalar
	s.SetByteSlice(signature[32:])
	s.Negate()
	sBytes := s.Bytes()
	copy(highS[32:], sBytes[:])
	if err := VerifyBindingSignature(fields, highS, pubKey); err == nil {
		t.Fatal("high-S signature accepted")
	}
}

func TestCRC16XModemKnownAnswer(t *testing.T) {
	// CRC-16/XMODEM check value for "123456789" is 0x31C3.
	if got := crc16XModem([]byte("123456789")); got != 0x31C3 {
		t.Fatalf("crc16 xmodem = %04x, want 31c3", got)
	}
}

// recomputeNATSUserPubkey decodes a user key, lets the caller alter the 32 key
// bytes and re-encodes with a fresh CRC, producing a different but well-formed
// key.
func recomputeNATSUserPubkey(t *testing.T, text string, alter func([]byte)) string {
	t.Helper()
	enc := base32NoPad()
	raw, err := enc.DecodeString(text)
	if err != nil || len(raw) != 35 {
		t.Fatalf("fixture pubkey does not decode: %v", err)
	}
	alter(raw[1:33])
	crc := crc16XModem(raw[:33])
	raw[33], raw[34] = byte(crc), byte(crc>>8)
	out := enc.EncodeToString(raw)
	if err := ValidateNATSUserPublicKey(out); err != nil {
		t.Fatalf("recomputed pubkey rejected: %v", err)
	}
	return out
}

func base32NoPad() *base32.Encoding {
	return base32.StdEncoding.WithPadding(base32.NoPadding)
}

func flipLastChar(text string) string {
	last := text[len(text)-1]
	if last == 'A' {
		return text[:len(text)-1] + "B"
	}
	return text[:len(text)-1] + "A"
}

func mustBindingWithSignature(t *testing.T, file bindingVectorFile, signature []byte) []byte {
	t.Helper()
	fields := bindingVectorFields(t, file, 0)
	var out []byte
	out = appendVarintField(out, 1, uint64(fields.SchemaVersion))
	out = appendBytesField(out, 2, []byte(fields.ChainID))
	out = appendVarintField(out, 3, uint64(uint32(fields.ParticipantType)))
	out = appendBytesField(out, 4, []byte(fields.OperatorAddress))
	out = appendVarintField(out, 5, fields.ServiceAuthorizationNonce)
	out = appendBytesField(out, 6, []byte(fields.NATSUserPubkey))
	out = appendVarintField(out, 7, fields.IssuedAtUnixMS)
	return appendBytesField(out, 8, signature)
}

// replaceByte swaps the first occurrence of the two-byte sequence a,b with c,d.
func replaceByte(raw []byte, a, b, c, d byte) []byte {
	out := append([]byte{}, raw...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == a && out[i+1] == b {
			out[i], out[i+1] = c, d
			return out
		}
	}
	return out
}
