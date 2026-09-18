package main

import (
	"fmt"
	"strings"
)

// This file carries a BIP-173 decoder rather than importing one. The tools
// module is deliberately stdlib-only — it has no go.sum — and a checker that
// exists to catch a hand-edited fixture is worth more when it depends on
// nothing that could itself drift. The algorithm is small and frozen by the
// BIP, so vendoring it costs less than the dependency would.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32MaxLength is the BIP-173 limit. Cosmos addresses are far shorter, so a
// vector that exceeds it is malformed rather than merely unusual.
const bech32MaxLength = 90

func bech32Polymod(values []byte) uint32 {
	generator := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i := 0; i < 5; i++ {
			if top>>uint(i)&1 == 1 {
				checksum ^= generator[i]
			}
		}
	}
	return checksum
}

func bech32ExpandHRP(hrp string) []byte {
	expanded := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]&31)
	}
	return expanded
}

// bech32ToBase256 regroups the 5-bit payload into bytes. The trailing partial
// group must be zero padding, otherwise the string encodes bits the address
// never had.
func bech32ToBase256(values []byte) ([]byte, error) {
	var (
		accumulator uint32
		bits        uint8
		out         []byte
	)
	for _, value := range values {
		accumulator = accumulator<<5 | uint32(value)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte(accumulator>>uint(bits)&0xff))
		}
	}
	if bits >= 5 {
		return nil, fmt.Errorf("payload has %d trailing bits, want fewer than 5", bits)
	}
	if accumulator<<(8-bits)&0xff != 0 {
		return nil, fmt.Errorf("payload has non-zero padding bits")
	}
	return out, nil
}

// decodeBech32 returns the human-readable part and the decoded address bytes,
// rejecting any string whose BIP-173 checksum does not verify.
func decodeBech32(encoded string) (string, []byte, error) {
	if len(encoded) > bech32MaxLength {
		return "", nil, fmt.Errorf("length %d exceeds the BIP-173 limit of %d", len(encoded), bech32MaxLength)
	}
	if strings.ToLower(encoded) != encoded {
		return "", nil, fmt.Errorf("must be lowercase")
	}
	separator := strings.LastIndexByte(encoded, '1')
	if separator < 1 || separator+7 > len(encoded) {
		return "", nil, fmt.Errorf("separator is missing or misplaced")
	}
	hrp := encoded[:separator]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", nil, fmt.Errorf("human-readable part holds byte %d outside [33,126]", hrp[i])
		}
	}
	payload := encoded[separator+1:]
	values := make([]byte, 0, len(payload))
	for i := 0; i < len(payload); i++ {
		index := strings.IndexByte(bech32Charset, payload[i])
		if index < 0 {
			return "", nil, fmt.Errorf("character %q is outside the Bech32 charset", payload[i])
		}
		values = append(values, byte(index))
	}
	if bech32Polymod(append(bech32ExpandHRP(hrp), values...)) != 1 {
		return "", nil, fmt.Errorf("checksum does not verify")
	}
	decoded, err := bech32ToBase256(values[:len(values)-6])
	if err != nil {
		return "", nil, err
	}
	return hrp, decoded, nil
}
