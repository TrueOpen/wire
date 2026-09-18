package bus

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
)

// ReplayRecord is one accepted envelope's replay entry. Two keys guard every
// envelope — one over message_id and one over nonce — both scoped to
// (chain_id, sender address-codec bytes, authorization_nonce) so one sender's
// identifiers cannot evict another's. The signing digest disambiguates retries: the same
// key with the same digest is a legal retransmission of the exact same bytes;
// the same key with a different digest is a replay or conflict.
type ReplayRecord struct {
	// ChainID scopes the keys to one chain.
	ChainID string
	// SenderOperator scopes the keys to one sender identity.
	SenderOperator string
	// AuthorizationNonce scopes the keys to one service-key generation.
	AuthorizationNonce uint64
	// MessageID is replay key one.
	MessageID string
	// Nonce is replay key two, the raw 32 bytes.
	Nonce []byte
	// SignDigest is the envelope signing digest that disambiguates retries.
	SignDigest [32]byte
	// TombstoneUntilMS keeps the entry at least until envelope expiry plus
	// the receiver's safety margin.
	TombstoneUntilMS uint64
}

// MessageKey is the message_id-scoped replay key.
func (r ReplayRecord) MessageKey() (string, error) {
	scope, err := r.operatorScope()
	if err != nil {
		return "", err
	}
	return scope + "m:" + r.MessageID, nil
}

// NonceKey is the nonce-scoped replay key.
func (r ReplayRecord) NonceKey() (string, error) {
	scope, err := r.operatorScope()
	if err != nil {
		return "", err
	}
	return scope + "n:" + hex.EncodeToString(r.Nonce), nil
}

// operatorScope is the (chain_id, sender, authorization_nonce) prefix both keys
// share. The sender enters as its 20 address-codec bytes rather than as text:
// live verification now rejects a foreign HRP before reaching this store, but
// codec-byte scoping remains defense in depth and keeps direct ReplayStore calls
// from creating separate text namespaces for one operator identity.
func (r ReplayRecord) operatorScope() (string, error) {
	operator, err := OperatorAddressCodecBytes(r.SenderOperator)
	if err != nil {
		return "", fmt.Errorf("%w: sender_operator: %v", ErrStoreFailure, err)
	}
	return r.ChainID + "\x00" + hex.EncodeToString(operator) + "\x00" +
		strconv.FormatUint(r.AuthorizationNonce, 10) + "\x00", nil
}

// ReplayStore is verification step 7. StoreOnce returns nil for a first
// occurrence and for a legal retry (same keys, same digest), wraps ErrReplay
// for a conflicting digest under either key, and wraps ErrStoreFailure for
// storage faults. Durable consumers must keep tombstones across restarts.
type ReplayStore interface {
	// StoreOnce records both keys of one accepted envelope.
	StoreOnce(record ReplayRecord, nowUnixMS uint64) error
}

// MemoryReplayStore is the in-process reference implementation, suitable for
// tests and as the semantic model for durable implementations.
type MemoryReplayStore struct {
	mu      sync.Mutex
	entries map[string]memoryReplayEntry
}

type memoryReplayEntry struct {
	signDigest       [32]byte
	tombstoneUntilMS uint64
}

// NewMemoryReplayStore returns an empty in-process replay store.
func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{entries: make(map[string]memoryReplayEntry)}
}

// StoreOnce implements ReplayStore with the reference semantics.
func (s *MemoryReplayStore) StoreOnce(record ReplayRecord, nowUnixMS uint64) error {
	if record.ChainID == "" || record.SenderOperator == "" || record.MessageID == "" ||
		len(record.Nonce) != NonceSize {
		return fmt.Errorf("%w: incomplete replay record", ErrStoreFailure)
	}
	messageKey, err := record.MessageKey()
	if err != nil {
		return err
	}
	nonceKey, err := record.NonceKey()
	if err != nil {
		return err
	}
	keys := []string{messageKey, nonceKey}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(nowUnixMS)
	for _, key := range keys {
		if existing, found := s.entries[key]; found && existing.signDigest != record.SignDigest {
			return fmt.Errorf("%w: same replay key with a different signing digest", ErrReplay)
		}
	}
	for _, key := range keys {
		s.entries[key] = memoryReplayEntry{signDigest: record.SignDigest, tombstoneUntilMS: record.TombstoneUntilMS}
	}
	return nil
}

func (s *MemoryReplayStore) pruneLocked(nowUnixMS uint64) {
	for key, entry := range s.entries {
		if entry.tombstoneUntilMS != 0 && nowUnixMS > entry.tombstoneUntilMS {
			delete(s.entries, key)
		}
	}
}
