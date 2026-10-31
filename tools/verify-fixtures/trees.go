package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/TrueOpen/wire/dispatch"
)

// The two tree framings hash the domain into every leaf and every interior
// node, so a vector that renames its domain without recomputing its root is
// pinning a preimage that no implementation can reproduce. Neither framing
// publishes a preimage_hex, which is why the preimage self-check in vectors.go
// never reached them.

// validatePublishedTreeRoot recomputes a published MERKLE_ROOT_V1 or
// MMR_ROOT_V1 root from the vector's own leaves. A tree vector carries leaves
// and a root but no preimage, so nothing else in this file can reach it.
func validatePublishedTreeRoot(where string, object map[string]any, domain, framing string) error {
	rootHex, hasRoot := object["root_hex"].(string)
	if !hasRoot {
		return nil
	}
	rawLeaves, hasLeaves := object["leaves_hex"].([]any)
	if !hasLeaves {
		return nil
	}
	leaves := make([][]byte, 0, len(rawLeaves))
	for index, value := range rawLeaves {
		leaf, err := decodePublishedHex(value)
		if err != nil {
			return fmt.Errorf("%s: leaf %d: %w", where, index, err)
		}
		leaves = append(leaves, leaf)
	}

	var got []byte
	switch framing {
	case "MERKLE_ROOT_V1":
		got = merkleRootV1(domain, leaves)
	case "MMR_ROOT_V1":
		got = mmrRootV1(domain, leaves)
	default:
		// A vector that publishes leaves and a root without naming its framing
		// cannot be checked, and silently skipping it is how a stale root
		// survives. MERKLE_ROOT_V1 is the only framing that ever omitted it.
		got = merkleRootV1(domain, leaves)
	}
	if hex.EncodeToString(got) != rootHex {
		return fmt.Errorf("%s: %s over %d leaves is %s, want %s",
			where, domain, len(leaves), hex.EncodeToString(got), rootHex)
	}
	return nil
}

// validatePublishedMutations checks the tamper and replay rows, which state
// that a named single-field change moves the digest. Neither was checked
// before, so a row could repeat the base digest and pin nothing at all.
func validatePublishedMutations(where string, object map[string]any, domain string) error {
	preimageHex, ok := object["preimage_hex"].(string)
	if !ok {
		return nil
	}
	preimage, err := decodePublishedHex(preimageHex)
	if err != nil {
		return nil
	}
	baseDigest := sha256.Sum256(preimage)
	base := hex.EncodeToString(baseDigest[:])

	parts, err := splitFramedPreimage(preimage)
	if err != nil || len(parts) == 0 || parts[0] != domain {
		// Only H_FIELDS_V1 preimages decompose this way; anything else is left
		// to the checks that already cover it.
		return nil
	}

	for _, row := range collectRows(object, "tamper") {
		digestHex, ok := row["digest_hex"].(string)
		if !ok {
			continue
		}
		if digestHex == base {
			return fmt.Errorf("%s: tamper %q repeats the base digest", where, rowName(row))
		}
	}
	for _, row := range collectRows(object, "replay") {
		digestHex, ok := row["digest_hex"].(string)
		if !ok {
			continue
		}
		if digestHex == base {
			return fmt.Errorf("%s: replay %q repeats the base digest, so it pins nothing",
				where, rowName(row))
		}
	}
	return nil
}

func collectRows(object map[string]any, key string) []map[string]any {
	raw, ok := object[key].([]any)
	if !ok {
		return nil
	}
	rows := make([]map[string]any, 0, len(raw))
	for _, value := range raw {
		if row, ok := value.(map[string]any); ok {
			rows = append(rows, row)
		}
	}
	return rows
}

func rowName(row map[string]any) string {
	if name, ok := row["name"].(string); ok {
		return name
	}
	return "?"
}

// splitFramedPreimage reads back the u64be length prefixes an H_FIELDS_V1
// preimage is built from. The first part is the domain literal.
func splitFramedPreimage(preimage []byte) ([]string, error) {
	var parts []string
	for offset := 0; offset < len(preimage); {
		if offset+8 > len(preimage) {
			return nil, fmt.Errorf("truncated length prefix")
		}
		size := binary.BigEndian.Uint64(preimage[offset : offset+8])
		offset += 8
		if uint64(len(preimage)-offset) < size {
			return nil, fmt.Errorf("truncated field")
		}
		parts = append(parts, string(preimage[offset:offset+int(size)]))
		offset += int(size)
	}
	return parts, nil
}

// treeDomainFrame is u32be(len(domain)) || domain, the prefix both tree
// framings bind every hash to.
// merkleRootV1 folds a binary tree left to right, promoting a lone trailing
// node instead of duplicating it.
func merkleRootV1(domain string, leaves [][]byte) []byte {
	return dispatch.MerkleRootV1(domain, leaves)
}

// mmrRootV1 appends leaves in order, merging equal-height peaks, then bags the
// remaining peaks right to left. The leaf hash binds the leaf's index and
// length so a reordering cannot produce the same root.
func mmrRootV1(domain string, leaves [][]byte) []byte { return dispatch.MMRRootV1(domain, leaves) }
