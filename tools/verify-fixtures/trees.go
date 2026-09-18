package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// The two tree framings hash the domain into every leaf and every interior
// node, so a vector that renames its domain without recomputing its root is
// pinning a preimage that no implementation can reproduce. Neither framing
// publishes a preimage_hex, which is why the preimage self-check in vectors.go
// never reached them.
const (
	merkleLeafPrefix  = "TRUEOPEN_MERKLE_LEAF_V1"
	merkleNodePrefix  = "TRUEOPEN_MERKLE_NODE_V1"
	merkleEmptyPrefix = "TRUEOPEN_MERKLE_EMPTY_V1"

	mmrLeafPrefix  = "TRUEOPEN_MMR_LEAF_V1"
	mmrNodePrefix  = "TRUEOPEN_MMR_NODE_V1"
	mmrEmptyPrefix = "TRUEOPEN_MMR_EMPTY_V1"
)

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
func treeDomainFrame(domain string) []byte {
	framed := make([]byte, 4+len(domain))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(domain)))
	copy(framed[4:], domain)
	return framed
}

func treeHash(parts ...[]byte) []byte {
	digest := sha256.New()
	for _, part := range parts {
		_, _ = digest.Write(part)
	}
	return digest.Sum(nil)
}

// merkleRootV1 folds a binary tree left to right, promoting a lone trailing
// node instead of duplicating it.
func merkleRootV1(domain string, leaves [][]byte) []byte {
	frame := treeDomainFrame(domain)
	if len(leaves) == 0 {
		return treeHash([]byte(merkleEmptyPrefix), frame)
	}
	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = treeHash([]byte(merkleLeafPrefix), frame, leaf)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, treeHash([]byte(merkleNodePrefix), frame, level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// mmrRootV1 appends leaves in order, merging equal-height peaks, then bags the
// remaining peaks right to left. The leaf hash binds the leaf's index and
// length so a reordering cannot produce the same root.
func mmrRootV1(domain string, leaves [][]byte) []byte {
	frame := treeDomainFrame(domain)
	if len(leaves) == 0 {
		return treeHash([]byte(mmrEmptyPrefix), frame)
	}
	type peak struct {
		height uint8
		hash   []byte
	}
	peaks := make([]peak, 0, 64)
	for index, leaf := range leaves {
		var indexBytes, lengthBytes [8]byte
		binary.BigEndian.PutUint64(indexBytes[:], uint64(index))
		binary.BigEndian.PutUint64(lengthBytes[:], uint64(len(leaf)))
		current := peak{hash: treeHash([]byte(mmrLeafPrefix), frame, indexBytes[:], lengthBytes[:], leaf)}
		for len(peaks) != 0 && peaks[len(peaks)-1].height == current.height {
			left := peaks[len(peaks)-1]
			peaks = peaks[:len(peaks)-1]
			current.hash = treeHash([]byte(mmrNodePrefix), frame, left.hash, current.hash)
			current.height++
		}
		peaks = append(peaks, current)
	}
	root := peaks[len(peaks)-1].hash
	for index := len(peaks) - 2; index >= 0; index-- {
		root = treeHash([]byte(mmrNodePrefix), frame, peaks[index].hash, root)
	}
	return root
}
