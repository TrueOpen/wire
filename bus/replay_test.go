package bus

import (
	"errors"
	"testing"

	"github.com/cosmos/btcutil/bech32"
)

func replayRecord() ReplayRecord {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = 0xAB
	}
	return ReplayRecord{
		ChainID:            "trueopen-localnet-1",
		SenderOperator:     canonicalOperatorAddress,
		AuthorizationNonce: 7,
		MessageID:          "01890000-0000-7000-8000-000000000000",
		Nonce:              nonce,
		SignDigest:         [32]byte{0xCC},
		TombstoneUntilMS:   2_000,
	}
}

func TestReplayStoreDualKeySemantics(t *testing.T) {
	store := NewMemoryReplayStore()
	record := replayRecord()

	if err := store.StoreOnce(record, 1_000); err != nil {
		t.Fatalf("first store: %v", err)
	}
	// Same keys, same digest: legal retry.
	if err := store.StoreOnce(record, 1_000); err != nil {
		t.Fatalf("legal retry rejected: %v", err)
	}
	// Same message_id, different digest: replay.
	conflicting := record
	conflicting.SignDigest = [32]byte{0xDD}
	if err := store.StoreOnce(conflicting, 1_000); !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want replay conflict on message_id", err)
	}
	// New message_id but reused nonce: the second key must catch it.
	reusedNonce := record
	reusedNonce.MessageID = "01890000-0000-7000-8000-000000000001"
	reusedNonce.SignDigest = [32]byte{0xEE}
	if err := store.StoreOnce(reusedNonce, 1_000); !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want replay conflict on nonce", err)
	}
	// After the tombstone expires the key is free again.
	if err := store.StoreOnce(conflicting, record.TombstoneUntilMS+1); err != nil {
		t.Fatalf("post-tombstone store: %v", err)
	}
}

// TestReplayKeysScopeBySenderCodecBytes covers the same evasion as
// TestEquivocationPreconditionsIdentifySenderByCodecBytes, one layer earlier.
// Live verification rejects a foreign HRP before replay, while this direct-store
// test keeps the lower layer scoped by codec bytes as defense in depth: one
// operator identity never receives two text-keyed replay namespaces.
func TestReplayKeysScopeBySenderCodecBytes(t *testing.T) {
	store := NewMemoryReplayStore()
	record := replayRecord()
	if err := store.StoreOnce(record, 1_000); err != nil {
		t.Fatalf("first store: %v", err)
	}

	codec, err := OperatorAddressCodecBytes(record.SenderOperator)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := bech32.EncodeFromBase256("cosmos", codec)
	if err != nil {
		t.Fatal(err)
	}
	if foreign == record.SenderOperator {
		t.Fatal("the two spellings are identical, so this proves nothing")
	}

	// Same sender, same keys, a conflicting digest: the prefix must not buy a
	// fresh namespace.
	conflicting := record
	conflicting.SenderOperator = foreign
	conflicting.SignDigest = [32]byte{0xDD}
	if err := store.StoreOnce(conflicting, 1_000); !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want replay conflict across bech32 prefixes", err)
	}

	// A different operator still gets its own namespace.
	other := make([]byte, len(codec))
	copy(other, codec)
	other[0] ^= 0xFF
	elsewhere, err := bech32.EncodeFromBase256("trueopen", other)
	if err != nil {
		t.Fatal(err)
	}
	separate := conflicting
	separate.SenderOperator = elsewhere
	if err := store.StoreOnce(separate, 1_000); err != nil {
		t.Fatalf("a different operator was evicted by the first one's keys: %v", err)
	}
}

// TestReplayKeysRejectUnusableSenderAddress pins the failure mode of a record
// whose sender cannot be decoded. The keys are the store's whole guarantee, so a
// record that cannot produce them must be a store failure and never a silent
// fallback to the raw text.
func TestReplayKeysRejectUnusableSenderAddress(t *testing.T) {
	store := NewMemoryReplayStore()
	record := replayRecord()
	record.SenderOperator = "trueopen1operator"
	if err := store.StoreOnce(record, 1_000); !errors.Is(err, ErrStoreFailure) {
		t.Fatalf("err = %v, want store failure for an undecodable sender", err)
	}
}

func TestReplayStoreRejectsIncompleteRecords(t *testing.T) {
	store := NewMemoryReplayStore()
	record := replayRecord()
	record.Nonce = record.Nonce[:16]
	if err := store.StoreOnce(record, 1_000); !errors.Is(err, ErrStoreFailure) {
		t.Fatalf("err = %v, want store failure for short nonce", err)
	}
}
