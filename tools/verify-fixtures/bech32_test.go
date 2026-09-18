package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestDecodeBech32BIP173Vectors pins the decoder against the BIP-173 test
// vectors. The valid half proves the checksum and the 5-to-8 bit regrouping
// agree with the specification; the invalid half proves each rejection reason
// is actually reached, because a decoder that accepts everything would let the
// fixture check pass on a corrupt address just as silently as no check at all.
func TestDecodeBech32BIP173Vectors(t *testing.T) {
	valid := map[string]string{
		"A12UEL5L": "a",
		"a12uel5l": "a",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs": "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw":                                              "abcdef",
		"?1ezyfcl": "?",
	}
	for encoded, wantHRP := range valid {
		lowered := strings.ToLower(encoded)
		hrp, _, err := decodeBech32(lowered)
		if err != nil {
			t.Fatalf("valid vector %q rejected: %v", lowered, err)
		}
		if hrp != strings.ToLower(wantHRP) {
			t.Fatalf("vector %q decoded HRP %q, want %q", lowered, hrp, wantHRP)
		}
	}

	invalid := []string{
		"pzry9x0s0muk",  // no separator
		"1pzry9x0s0muk", // empty human-readable part
		"x1b4n0q5v",     // invalid data character
		"li1dgmt3",      // checksum too short
		"A1G7SGD8",      // checksum does not verify
		"10a06t8",       // empty human-readable part
		"1qzzfhee",      // empty human-readable part
		"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", // over length
	}
	for _, encoded := range invalid {
		if _, _, err := decodeBech32(strings.ToLower(encoded)); err == nil {
			t.Fatalf("invalid vector %q accepted", encoded)
		}
	}
}

// TestDecodeBech32TrueOpenAddress pins the exact pair this check was added for: a
// TrueOpen address whose Bech32 column had been hand-written with a checksum that
// never verified, alongside the string the shared hex re-encodes to.
func TestDecodeBech32TrueOpenAddress(t *testing.T) {
	const (
		address = "trueopen1crqu9s7ychrv0jxfet9uenwwelgdr5knutsmxe"
		corrupt = "trueopen1cxphpv8x9ceruv3jt9vueeh88ap5w6tfrx7v3l"
		payload = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3"
	)
	hrp, decoded, err := decodeBech32(address)
	if err != nil {
		t.Fatalf("trueopen address rejected: %v", err)
	}
	if hrp != fixtureAddressHRP {
		t.Fatalf("decoded HRP %q, want %q", hrp, fixtureAddressHRP)
	}
	if got := hex.EncodeToString(decoded); got != payload {
		t.Fatalf("decoded %s, want %s", got, payload)
	}
	if _, _, err := decodeBech32(corrupt); err == nil {
		t.Fatal("corrupt trueopen address accepted")
	}
}

func TestDecodeBech32RejectsMixedCase(t *testing.T) {
	if _, _, err := decodeBech32("TrueOpen1crqu9s7ychrv0jxfet9uenwwelgdr5kncw5gu3"); err == nil {
		t.Fatal("mixed-case address accepted")
	}
}
