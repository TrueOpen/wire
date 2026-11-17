package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/TrueOpen/wire/tokenids"
)

type inputTokenCountFixture struct {
	Vectors []struct {
		Name  string `json:"name"`
		Raw   string `json:"token_ids_raw_hex"`
		Count uint64 `json:"token_count"`
	} `json:"vectors"`
	Derivation struct {
		SourceCase string                `json:"source_case"`
		Cases      []inputTokenCountCase `json:"cases"`
	} `json:"input_token_count_derivation"`
}

type inputTokenCountCase struct {
	Name      string  `json:"name"`
	Size      string  `json:"encoded_size_bytes"`
	Generated string  `json:"generated_token_count"`
	Input     *string `json:"input_token_count"`
}

// Execute the published cases in the ordinary manifest gate, not only tests.
// The source example must still agree with the existing raw token artifacts.
func validateInputTokenCountCases(raw []byte) error {
	var fixture inputTokenCountFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return err
	}
	if len(fixture.Derivation.Cases) == 0 || fixture.Derivation.SourceCase == "" {
		return fmt.Errorf("missing input token count derivation cases or source case")
	}
	artifacts := map[string]struct{ size, count uint64 }{}
	for _, vector := range fixture.Vectors {
		encoded, err := hex.DecodeString(vector.Raw)
		if err != nil || len(encoded) < 4 || uint64(binary.BigEndian.Uint32(encoded[:4])) != vector.Count ||
			uint64(len(encoded)-4) != vector.Count*4 {
			return fmt.Errorf("%s: token count does not match its raw artifact", vector.Name)
		}
		artifacts[vector.Name] = struct{ size, count uint64 }{uint64(len(encoded)), vector.Count}
	}
	input, hasInput := artifacts["input_token_ids_v1"]
	generated, hasGenerated := artifacts["generated_token_ids_v1"]
	if !hasInput || !hasGenerated {
		return fmt.Errorf("missing source input/generated token-ID artifacts")
	}
	seen := map[string]bool{}
	for _, row := range fixture.Derivation.Cases {
		if row.Name == "" || seen[row.Name] {
			return fmt.Errorf("missing or duplicate input token count case %q", row.Name)
		}
		seen[row.Name] = true
		size, err := strconv.ParseUint(row.Size, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: invalid encoded size: %w", row.Name, err)
		}
		count, err := strconv.ParseUint(row.Generated, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: invalid generated count: %w", row.Name, err)
		}
		got, deriveErr := tokenids.InputTokenCountV1(size, count)
		if row.Input == nil {
			if deriveErr == nil {
				return fmt.Errorf("%s: unavailable case produced %d", row.Name, got)
			}
		} else {
			want, err := strconv.ParseUint(*row.Input, 10, 64)
			if err != nil || deriveErr != nil || got != want {
				return fmt.Errorf("%s: derived %d (%v), want %s", row.Name, got, deriveErr, *row.Input)
			}
		}
		if row.Name == fixture.Derivation.SourceCase &&
			(deriveErr != nil || size != input.size+generated.size || count != generated.count || got != input.count) {
			return fmt.Errorf("%s: source case diverges from the raw token-ID artifacts", row.Name)
		}
	}
	if !seen[fixture.Derivation.SourceCase] {
		return fmt.Errorf("missing input token count source case %q", fixture.Derivation.SourceCase)
	}
	return nil
}
