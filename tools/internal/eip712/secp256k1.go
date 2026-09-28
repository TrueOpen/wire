package eip712

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// secp256k1 domain parameters (SEC 2, section 2.4.1).
var (
	fieldP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	orderN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	halfN     = new(big.Int).Rsh(orderN, 1)
	baseG     = point{
		x: mustBig("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		y: mustBig("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
	}
)

func mustBig(text string) *big.Int {
	value, ok := new(big.Int).SetString(text, 16)
	if !ok {
		panic("bad constant " + text)
	}
	return value
}

// point is an affine curve point; a nil x is the point at infinity.
type point struct{ x, y *big.Int }

func (p point) infinity() bool { return p.x == nil }

func mod(value, modulus *big.Int) *big.Int {
	return new(big.Int).Mod(value, modulus)
}

func add(p, q point) point {
	switch {
	case p.infinity():
		return q
	case q.infinity():
		return p
	}
	var slope *big.Int
	if p.x.Cmp(q.x) == 0 {
		if mod(new(big.Int).Add(p.y, q.y), fieldP).Sign() == 0 {
			return point{}
		}
		// Doubling: (3x^2) / (2y); the curve's a is 0.
		numerator := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.x, p.x))
		denominator := new(big.Int).ModInverse(mod(new(big.Int).Lsh(p.y, 1), fieldP), fieldP)
		slope = mod(new(big.Int).Mul(numerator, denominator), fieldP)
	} else {
		numerator := new(big.Int).Sub(q.y, p.y)
		denominator := new(big.Int).ModInverse(mod(new(big.Int).Sub(q.x, p.x), fieldP), fieldP)
		slope = mod(new(big.Int).Mul(numerator, denominator), fieldP)
	}
	x := mod(new(big.Int).Sub(new(big.Int).Mul(slope, slope), new(big.Int).Add(p.x, q.x)), fieldP)
	y := mod(new(big.Int).Sub(new(big.Int).Mul(slope, new(big.Int).Sub(p.x, x)), p.y), fieldP)
	return point{x: x, y: y}
}

func multiply(p point, scalar *big.Int) point {
	result := point{}
	for i := scalar.BitLen() - 1; i >= 0; i-- {
		result = add(result, result)
		if scalar.Bit(i) == 1 {
			result = add(result, p)
		}
	}
	return result
}

func be32(value *big.Int) []byte {
	return value.FillBytes(make([]byte, 32))
}

// Key is a secp256k1 private key and what the fixtures derive from it.
type Key struct {
	scalar *big.Int
	public point
}

// ParseKey reads a 32-byte private key given as lowercase hex.
func ParseKey(privateHex string) (Key, error) {
	raw, err := hex.DecodeString(privateHex)
	if err != nil || len(raw) != 32 {
		return Key{}, errors.New("private key must be 32 bytes of hex")
	}
	scalar := new(big.Int).SetBytes(raw)
	if scalar.Sign() == 0 || scalar.Cmp(orderN) >= 0 {
		return Key{}, errors.New("private key is outside [1, n-1]")
	}
	return Key{scalar: scalar, public: multiply(baseG, scalar)}, nil
}

// PublicXY is the 64-byte uncompressed public key without its 0x04 prefix.
func (k Key) PublicXY() []byte {
	return append(be32(k.public.x), be32(k.public.y)...)
}

// PublicCompressed is the 33-byte SEC 1 compressed public key.
func (k Key) PublicCompressed() []byte {
	prefix := byte(0x02)
	if k.public.y.Bit(0) == 1 {
		prefix = 0x03
	}
	return append([]byte{prefix}, be32(k.public.x)...)
}

// Address is the last 20 bytes of keccak256 over the uncompressed X||Y.
func (k Key) Address() [20]byte {
	return addressOf(k.public)
}

func addressOf(p point) [20]byte {
	digest := Keccak256(be32(p.x), be32(p.y))
	var out [20]byte
	copy(out[:], digest[12:])
	return out
}

// ChecksumAddress is the EIP-55 mixed-case 0x form of a 20-byte address.
func ChecksumAddress(address [20]byte) string {
	lower := hex.EncodeToString(address[:])
	digest := Keccak256([]byte(lower))
	var out strings.Builder
	out.WriteString("0x")
	for i, char := range lower {
		nibble := digest[i/2] >> 4
		if i%2 == 1 {
			nibble = digest[i/2] & 0x0f
		}
		if char >= 'a' && nibble >= 8 {
			out.WriteRune(char - 'a' + 'A')
		} else {
			out.WriteRune(char)
		}
	}
	return out.String()
}

// rfc6979Nonces yields the RFC 6979 section 3.2 candidates for a 32-byte digest
// with HMAC-SHA256, the sequence secp256k1 signers use when no extra entropy is
// supplied. The caller takes the first candidate that yields a valid signature.
func rfc6979Nonces(scalar *big.Int, digest []byte) func() *big.Int {
	x := be32(scalar)
	h := be32(mod(new(big.Int).SetBytes(digest), orderN))
	mac := func(key []byte, parts ...[]byte) []byte {
		m := hmac.New(sha256.New, key)
		for _, part := range parts {
			m.Write(part)
		}
		return m.Sum(nil)
	}
	v := make([]byte, 32)
	for i := range v {
		v[i] = 0x01
	}
	k := make([]byte, 32)
	k = mac(k, v, []byte{0x00}, x, h)
	v = mac(k, v)
	k = mac(k, v, []byte{0x01}, x, h)
	v = mac(k, v)
	first := true
	return func() *big.Int {
		for {
			if !first {
				k = mac(k, v, []byte{0x00})
				v = mac(k, v)
			}
			first = false
			v = mac(k, v)
			candidate := new(big.Int).SetBytes(v)
			if candidate.Sign() > 0 && candidate.Cmp(orderN) < 0 {
				return candidate
			}
		}
	}
}

// Sign returns the 65-byte R||S||V signature over a 32-byte digest, with a
// deterministic RFC 6979 nonce, low S, and V in {27, 28}. The digest is signed
// as given and never hashed again.
func (k Key) Sign(digest [32]byte) []byte {
	next := rfc6979Nonces(k.scalar, digest[:])
	e := new(big.Int).SetBytes(digest[:])
	for {
		nonce := next()
		r := multiply(baseG, nonce)
		rx := mod(r.x, orderN)
		if rx.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(rx, k.scalar)
		s.Add(s, e)
		s.Mul(s, new(big.Int).ModInverse(nonce, orderN))
		s.Mod(s, orderN)
		if s.Sign() == 0 {
			continue
		}
		recovery := byte(r.y.Bit(0))
		if r.x.Cmp(orderN) >= 0 {
			// R.x wrapped modulo n; the 65-byte form cannot express it, so a
			// signer that met this would have to pick another nonce.
			continue
		}
		if s.Cmp(halfN) > 0 {
			s.Sub(orderN, s)
			recovery ^= 1
		}
		return append(append(be32(rx), be32(s)...), 27+recovery)
	}
}

// Recover returns the address whose key produced a 65-byte R||S||V signature
// over digest. It enforces the canonical form the protocol requires: exactly 65
// bytes, V in {27, 28}, R and S in [1, n-1], and low S.
func Recover(digest [32]byte, signature []byte) ([20]byte, error) {
	if len(signature) != 65 {
		return [20]byte{}, errors.New("signature is not 65 bytes")
	}
	v := signature[64]
	if v != 27 && v != 28 {
		return [20]byte{}, errors.New("V is not 27 or 28")
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	if r.Sign() == 0 || r.Cmp(orderN) >= 0 || s.Sign() == 0 || s.Cmp(orderN) >= 0 {
		return [20]byte{}, errors.New("R or S is outside [1, n-1]")
	}
	if s.Cmp(halfN) > 0 {
		return [20]byte{}, errors.New("S is high")
	}
	// R = (r, y) with y of the parity V selects: y = sqrt(x^3 + 7) mod p, and
	// p = 3 mod 4 so the root is (x^3 + 7)^((p+1)/4).
	ySquared := mod(new(big.Int).Add(new(big.Int).Exp(r, big.NewInt(3), fieldP), big.NewInt(7)), fieldP)
	y := new(big.Int).Exp(ySquared, new(big.Int).Rsh(new(big.Int).Add(fieldP, big.NewInt(1)), 2), fieldP)
	if mod(new(big.Int).Mul(y, y), fieldP).Cmp(ySquared) != 0 {
		return [20]byte{}, errors.New("R is not on the curve")
	}
	if y.Bit(0) != uint(v-27) {
		y.Sub(fieldP, y)
	}
	// Q = r^-1 (sR - eG)
	e := mod(new(big.Int).SetBytes(digest[:]), orderN)
	rInverse := new(big.Int).ModInverse(r, orderN)
	sR := multiply(point{x: r, y: y}, s)
	eG := multiply(baseG, e)
	negEG := point{}
	if !eG.infinity() {
		negEG = point{x: eG.x, y: mod(new(big.Int).Neg(eG.y), fieldP)}
	}
	q := multiply(add(sR, negEG), rInverse)
	if q.infinity() {
		return [20]byte{}, errors.New("recovered the point at infinity")
	}
	return addressOf(q), nil
}
