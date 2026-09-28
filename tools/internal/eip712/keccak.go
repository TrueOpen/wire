// Package eip712 recomputes the EIP-712 values the fixtures publish: the
// type hash, domain separator, hash_struct and signing digest, and the
// recoverable secp256k1 signature over that digest.
//
// It is written from the specifications (FIPS 202 Keccak with the original
// 0x01 padding, SEC 1 and RFC 6979 for secp256k1, and EIP-712 itself) rather
// than imported, for two reasons. The tools module is dependency-free on
// purpose, and a verifier that shares its signing library with the code that
// produced a vector cannot catch a bug in that library. It is checked against
// the vectors Node produced before this package existed, and against published
// Keccak and secp256k1 test values in its own tests.
//
// None of this is constant-time. It handles public test keys only and must not
// be used for anything else.
package eip712

import (
	"encoding/binary"
	"math/bits"
)

// Keccak256 is the original Keccak with a 256-bit output and 0x01 padding, the
// hash Ethereum and EIP-712 use. It is not SHA3-256, which pads with 0x06.
func Keccak256(chunks ...[]byte) [32]byte {
	const rate = 136
	var state [25]uint64
	var buffer []byte
	for _, chunk := range chunks {
		buffer = append(buffer, chunk...)
	}
	// Pad: 0x01, zeros, and 0x80 in the last byte of the final block.
	padded := append([]byte(nil), buffer...)
	padded = append(padded, 0x01)
	for len(padded)%rate != 0 {
		padded = append(padded, 0)
	}
	padded[len(padded)-1] |= 0x80
	for offset := 0; offset < len(padded); offset += rate {
		for lane := 0; lane < rate/8; lane++ {
			state[lane] ^= binary.LittleEndian.Uint64(padded[offset+8*lane:])
		}
		keccakF1600(&state)
	}
	var out [32]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(out[8*lane:], state[lane])
	}
	return out
}

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// rotationOffsets[x+5y] is the rho rotation of lane (x, y).
var rotationOffsets = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// keccakF1600 is the permutation, lanes indexed x+5y.
func keccakF1600(a *[25]uint64) {
	var b [25]uint64
	var c, d [5]uint64
	for round := 0; round < 24; round++ {
		// theta
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for i := 0; i < 25; i++ {
			a[i] ^= d[i%5]
		}
		// rho and pi: lane (x, y) moves to (y, 2x+3y).
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], rotationOffsets[x+5*y])
			}
		}
		// chi
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] = b[x+5*y] ^ (^b[(x+1)%5+5*y] & b[(x+2)%5+5*y])
			}
		}
		// iota
		a[0] ^= roundConstants[round]
	}
}
