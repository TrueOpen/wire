package bus

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cosmos/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type fixture struct {
	fields    Fields
	payload   []byte
	signature []byte
	opts      VerifyOptions
	privKey   *secp256k1.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	seed := sha256.Sum256([]byte("bus verify fixture key"))
	privKey := secp256k1.PrivKeyFromBytes(seed[:])
	payload := []byte{0x0a, 0x01, 0x01}
	payloadDigest := PayloadDigest(payload)
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	fields := Fields{
		SchemaVersion:             1,
		ChainID:                   "trueopen-localnet-1",
		Subject:                   "trueopen.handraise.worker.task-1",
		Kind:                      KindWorkerHandraise,
		SenderParticipantType:     ParticipantCortex,
		SenderOperatorAddress:     "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut",
		ServiceAuthorizationNonce: 7,
		MessageID:                 "01890000-0000-7000-8000-000000000001",
		Nonce:                     nonce,
		IssuedAtUnixMS:            1_700_000_000_000,
		ExpiresAtUnixMS:           1_700_000_060_000,
		PayloadType:               PayloadTypeWorkerHandraiseV1,
		PayloadDigest:             payloadDigest[:],
	}
	digest, err := SigningDigest(fields)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(participantType int32, operator string) (KeyBinding, error) {
		if participantType != fields.SenderParticipantType || operator != fields.SenderOperatorAddress {
			return KeyBinding{}, errors.New("unknown operator")
		}
		return KeyBinding{
			PubKeyCompressed:   privKey.PubKey().SerializeCompressed(),
			AuthorizationNonce: 7,
			Active:             true,
		}, nil
	}
	return &fixture{
		fields:    fields,
		payload:   payload,
		signature: SignDigest(privKey, digest),
		privKey:   privKey,
		opts: VerifyOptions{
			ChainID:              "trueopen-localnet-1",
			Subject:              fields.Subject,
			NowUnixMS:            1_700_000_030_000,
			RawSize:              512,
			LookupKey:            lookup,
			Replay:               NewMemoryReplayStore(),
			ReplaySafetyMarginMS: 60_000,
		},
	}
}

func TestVerifyAcceptsAndAllowsExactRetry(t *testing.T) {
	fx := newFixture(t)
	if err := Verify(fx.fields, fx.payload, fx.signature, fx.opts); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Same bytes, same message_id and nonce: a legal retransmission.
	if err := Verify(fx.fields, fx.payload, fx.signature, fx.opts); err != nil {
		t.Fatalf("legal retry rejected: %v", err)
	}
}

// TestVerifyOrder breaks each step together with every later step and asserts
// the earlier step's class is reported, freezing the verification order.
func TestVerifyOrder(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*fixture)
		wantErr error
	}{
		{"size bound before everything", func(fx *fixture) {
			fx.opts.RawSize = MaxEnvelopeBytes + 1
			fx.fields.ChainID = "other"
		}, ErrStructure},
		{"raw size is required", func(fx *fixture) {
			fx.opts.RawSize = 0
		}, ErrStructure},
		{"structure before routing", func(fx *fixture) {
			fx.fields.SchemaVersion = 2
			fx.fields.Subject = "another.subject"
		}, ErrStructure},
		{"empty payload is structural", func(fx *fixture) {
			fx.payload = nil
		}, ErrStructure},
		{"routing before chain", func(fx *fixture) {
			fx.opts.Subject = "another.subject"
			fx.fields.ChainID = "other"
		}, ErrRouting},
		{"payload_type must match kind", func(fx *fixture) {
			fx.fields.PayloadType = PayloadTypeVerifyResultV1
		}, ErrRouting},
		{"chain before payload", func(fx *fixture) {
			fx.opts.ChainID = "other"
			fx.payload = []byte{0xff}
		}, ErrChainFresh},
		{"expiry", func(fx *fixture) {
			fx.opts.NowUnixMS = fx.fields.ExpiresAtUnixMS + 1
		}, ErrChainFresh},
		{"ttl bound", func(fx *fixture) {
			fx.fields.ExpiresAtUnixMS = fx.fields.IssuedAtUnixMS + MaxEnvelopeTTLMS + 1
		}, ErrChainFresh},
		{"payload before key binding", func(fx *fixture) {
			fx.payload = []byte{0xff}
			fx.opts.LookupKey = nil
		}, ErrPayload},
		{"key binding before signature", func(fx *fixture) {
			fx.opts.LookupKey = func(int32, string) (KeyBinding, error) {
				return KeyBinding{}, errors.New("lookup down")
			}
			fx.signature = make([]byte, SignatureSize)
		}, ErrKeyBinding},
		{"inactive binding", func(fx *fixture) {
			original := fx.opts.LookupKey
			fx.opts.LookupKey = func(p int32, o string) (KeyBinding, error) {
				binding, err := original(p, o)
				binding.Active = false
				return binding, err
			}
		}, ErrKeyBinding},
		{"authorization nonce mismatch", func(fx *fixture) {
			fx.fields.ServiceAuthorizationNonce = 8
		}, ErrKeyBinding},
		{"zeroed signature", func(fx *fixture) {
			fx.signature = make([]byte, SignatureSize)
		}, ErrSignature},
		{"payload tamper flips digest then signature holds it", func(fx *fixture) {
			fx.fields.PayloadDigest = make([]byte, sha256.Size)
			digest := PayloadDigest([]byte{0xEE})
			fx.fields.PayloadDigest = digest[:]
			fx.payload = []byte{0xEE}
		}, ErrSignature},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fx := newFixture(t)
			testCase.mutate(fx)
			err := Verify(fx.fields, fx.payload, fx.signature, fx.opts)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("err = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

// TestVerifyRejectsSignatureVariants pins the negative space of the signature
// rule: high-S, recoverable length, and the double-hash mistake.
func TestVerifyRejectsSignatureVariants(t *testing.T) {
	fx := newFixture(t)
	digest, err := SigningDigest(fx.fields)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := fx.privKey.PubKey().SerializeCompressed()

	t.Run("high-S variant", func(t *testing.T) {
		order, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
		s := new(big.Int).SetBytes(fx.signature[32:])
		high := new(big.Int).Sub(order, s)
		variant := make([]byte, SignatureSize)
		copy(variant[:32], fx.signature[:32])
		high.FillBytes(variant[32:])
		if err := VerifyDigestSignature(pubKey, digest[:], variant); err == nil {
			t.Fatal("high-S variant must be rejected")
		}
	})

	t.Run("65-byte recoverable length", func(t *testing.T) {
		variant := append(append([]byte(nil), fx.signature...), 0x01)
		if err := VerifyDigestSignature(pubKey, digest[:], variant); err == nil {
			t.Fatal("65-byte signature must be rejected")
		}
	})

	t.Run("double-hashed signature", func(t *testing.T) {
		rehashed := sha256.Sum256(digest[:])
		wrong := SignDigest(fx.privKey, rehashed)
		if err := VerifyDigestSignature(pubKey, digest[:], wrong); err == nil {
			t.Fatal("a signature over sha256(digest) must not verify against digest")
		}
	})
}

// canonicalOperatorAddress is a valid bech32 operator address with the chain
// prefix, shared by the tests that care about address spelling.
const canonicalOperatorAddress = "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"

// TestOperatorAddressSpellingIsCanonical covers the one place where the signing
// projection and the text it comes from can disagree. H_FIELDS_V1 frames only
// the 20 decoded bytes, and bech32 accepts an all-uppercase spelling of the same
// bytes, so without this rule one signature would be valid under two different
// sender_operator_address strings. The replay keys and EquivocationPreconditions
// no longer read the text, but key lookup and every consumer that stores or
// displays the address still do, and one identity with two spellings there is a
// defect of its own.
func TestOperatorAddressSpellingIsCanonical(t *testing.T) {
	const canonical = canonicalOperatorAddress

	want, err := OperatorAddressCodecBytes(canonical)
	if err != nil {
		t.Fatalf("the canonical spelling must decode: %v", err)
	}
	if len(want) != operatorAddressCodecSize {
		t.Fatalf("decoded %d bytes, want %d", len(want), operatorAddressCodecSize)
	}

	upper := strings.ToUpper(canonical)
	if upper == canonical {
		t.Fatal("the fixture has no case to change, so it proves nothing")
	}
	got, err := OperatorAddressCodecBytes(upper)
	if err == nil {
		t.Fatalf("accepted %q, which decodes to the same %x as the canonical spelling", upper, got)
	}
	if !strings.Contains(err.Error(), "canonical spelling") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

func TestLiveVerifyRejectsForeignHRPBeforeLookup(t *testing.T) {
	fx := newFixture(t)
	codec, err := OperatorAddressCodecBytes(fx.fields.SenderOperatorAddress)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := bech32.EncodeFromBase256("cosmos", codec)
	if err != nil {
		t.Fatal(err)
	}
	fx.fields.SenderOperatorAddress = foreign
	lookups := 0
	fx.opts.LookupKey = func(int32, string) (KeyBinding, error) {
		lookups++
		return KeyBinding{}, nil
	}
	if err := Verify(fx.fields, fx.payload, fx.signature, fx.opts); !errors.Is(err, ErrStructure) {
		t.Fatalf("Verify error = %v, want ErrStructure", err)
	}
	if lookups != 0 {
		t.Fatalf("key lookup ran %d time(s) before foreign-HRP rejection", lookups)
	}
	if _, err := SigningPreimage(fx.fields); err == nil {
		t.Fatal("sender-side signing accepted a foreign HRP")
	}
}
