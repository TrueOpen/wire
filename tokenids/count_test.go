package tokenids_test

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/TrueOpen/wire/tokenids"
)

func TestInputTokenCountV1PublishedVectors(t *testing.T) {
	raw, err := os.ReadFile("../testdata/v1/task/token_ids_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Derivation struct {
			Cases []struct {
				Name      string  `json:"name"`
				Size      string  `json:"encoded_size_bytes"`
				Generated string  `json:"generated_token_count"`
				Input     *string `json:"input_token_count"`
			} `json:"cases"`
		} `json:"input_token_count_derivation"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Derivation.Cases) == 0 {
		t.Fatal("missing input token count cases")
	}
	for _, row := range fixture.Derivation.Cases {
		t.Run(row.Name, func(t *testing.T) {
			parse := func(text string) uint64 {
				value, err := strconv.ParseUint(text, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			got, err := tokenids.InputTokenCountV1(parse(row.Size), parse(row.Generated))
			if row.Input == nil {
				if !errors.Is(err, tokenids.ErrInputTokenCountUnavailable) || got != 0 {
					t.Fatalf("got %d, %v; want unavailable", got, err)
				}
			} else if err != nil || got != parse(*row.Input) {
				t.Fatalf("got %d, %v; want %s", got, err, *row.Input)
			}
		})
	}
}

// Build actual counted artifacts independently of the derivation arithmetic.
// Repeated and unordered IDs must not affect the count derived from their size.
func TestInputTokenCountV1MatchesEncodedArtifacts(t *testing.T) {
	artifact := func(count uint32) []byte {
		raw := binary.BigEndian.AppendUint32(nil, count)
		for i := uint32(0); i < count; i++ {
			raw = binary.BigEndian.AppendUint32(raw, (count-i)%3)
		}
		return raw
	}
	for input := uint32(1); input <= 64; input++ {
		for generated := uint32(0); generated <= 64; generated++ {
			inputRaw, generatedRaw := artifact(input), artifact(generated)
			got, err := tokenids.InputTokenCountV1(uint64(len(inputRaw)+len(generatedRaw)), uint64(generated))
			if err != nil || got != uint64(input) {
				t.Fatalf("input %d generated %d: got %d, %v", input, generated, got, err)
			}
		}
	}
}
