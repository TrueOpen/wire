package dispatch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const handraiseMerkleDomain = "TRUEOPEN_HANDRAISE_MERKLE_V1"

func treeHash(parts ...[]byte) []byte {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

func treeDomain(domain string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(domain))), []byte(domain)...)
}

func merkleFold(domain string, leaves [][]byte, visit func([][]byte)) []byte {
	framed := treeDomain(domain)
	if len(leaves) == 0 {
		return treeHash([]byte("TRUEOPEN_MERKLE_EMPTY_V1"), framed)
	}
	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = treeHash([]byte("TRUEOPEN_MERKLE_LEAF_V1"), framed, leaf)
	}
	for len(level) > 1 {
		if visit != nil {
			visit(level)
		}
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, treeHash([]byte("TRUEOPEN_MERKLE_NODE_V1"), framed, level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// MerkleRootV1 reuses the canonical domain-bound tree with odd-node promotion.
// The fixture checker consumes this same implementation instead of a copy.
func MerkleRootV1(domain string, leaves [][]byte) []byte { return merkleFold(domain, leaves, nil) }

// HandraiseLeafDigest commits one explicit admission decision.
func HandraiseLeafDigest(standing [32]byte, admitted bool, reason uint32, rtt uint64) ([32]byte, error) {
	if admitted && (reason != 1 || rtt != 0) || !admitted && (reason < 2 || reason > 4 || reason == 2 && rtt == 0 || reason != 2 && rtt != 0) {
		return [32]byte{}, fmt.Errorf("invalid handraise admission decision")
	}
	flag := byte(0)
	if admitted {
		flag = 1
	}
	return HashFields("TRUEOPEN_HANDRAISE_ROOT_LEAF_V1", standing[:], []byte{flag}, Uint32(reason), Uint64(rtt)), nil
}

// HandraiseRoot builds the tree over admission leaf digests in ascending
// standing_handraise_digest order, as provided by the canonical root producer.
func HandraiseRoot(leaves [][32]byte) [32]byte {
	parts := make([][]byte, len(leaves))
	for i := range leaves {
		parts[i] = leaves[i][:]
	}
	var out [32]byte
	copy(out[:], MerkleRootV1(handraiseMerkleDomain, parts))
	return out
}

// HandraiseProof returns precisely the siblings needed for the selected leaf.
func HandraiseProof(leaves [][32]byte, index uint32) ([][32]byte, error) {
	if len(leaves) == 0 || uint64(index) >= uint64(len(leaves)) {
		return nil, fmt.Errorf("invalid handraise leaf index")
	}
	parts := make([][]byte, len(leaves))
	for i := range leaves {
		parts[i] = leaves[i][:]
	}
	position := int(index)
	var siblings [][32]byte
	merkleFold(handraiseMerkleDomain, parts, func(level [][]byte) {
		other := position ^ 1
		if other < len(level) {
			var sibling [32]byte
			copy(sibling[:], level[other])
			siblings = append(siblings, sibling)
		}
		position /= 2
	})
	return siblings, nil
}

// VerifyHandraiseProof rejects extra, missing and reordered siblings, including
// paths that incorrectly duplicate a promoted odd trailing node.
func VerifyHandraiseProof(root, leaf [32]byte, index, count uint32, siblings [][32]byte) bool {
	return VerifyMerkleProofV1(handraiseMerkleDomain, root, leaf, uint64(index), uint64(count), siblings)
}

// VerifyMerkleProofV1 verifies the same domain-bound tree used by MerkleRootV1.
// Values are leaf digests; odd trailing nodes are promoted, never duplicated.
func VerifyMerkleProofV1(domain string, root, leaf [32]byte, index, count uint64, siblings [][32]byte) bool {
	if count == 0 || index >= count {
		return false
	}
	framed := treeDomain(domain)
	current := treeHash([]byte("TRUEOPEN_MERKLE_LEAF_V1"), framed, leaf[:])
	used := 0
	for count > 1 {
		if index^1 < count {
			if used == len(siblings) {
				return false
			}
			sibling := siblings[used]
			used++
			if index&1 == 0 {
				current = treeHash([]byte("TRUEOPEN_MERKLE_NODE_V1"), framed, current, sibling[:])
			} else {
				current = treeHash([]byte("TRUEOPEN_MERKLE_NODE_V1"), framed, sibling[:], current)
			}
		}
		index /= 2
		count = count/2 + count%2
	}
	return used == len(siblings) && string(current) == string(root[:])
}

// MMRRootV1 is the shared index- and length-bound streaming commitment.
func MMRRootV1(domain string, leaves [][]byte) []byte {
	frame := treeDomain(domain)
	if len(leaves) == 0 {
		return treeHash([]byte("TRUEOPEN_MMR_EMPTY_V1"), frame)
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
		current := peak{hash: treeHash([]byte("TRUEOPEN_MMR_LEAF_V1"), frame, indexBytes[:], lengthBytes[:], leaf)}
		for len(peaks) != 0 && peaks[len(peaks)-1].height == current.height {
			left := peaks[len(peaks)-1]
			peaks = peaks[:len(peaks)-1]
			current.hash = treeHash([]byte("TRUEOPEN_MMR_NODE_V1"), frame, left.hash, current.hash)
			current.height++
		}
		peaks = append(peaks, current)
	}
	root := peaks[len(peaks)-1].hash
	for index := len(peaks) - 2; index >= 0; index-- {
		root = treeHash([]byte("TRUEOPEN_MMR_NODE_V1"), frame, peaks[index].hash, root)
	}
	return root
}
