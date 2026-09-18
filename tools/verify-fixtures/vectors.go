package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const trueOpenFrameMagic = "TRUEOPEN_FRAME_V1"

func validatePublishedVectors(path, declaredPath string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	legacyUpperHex := hex.EncodeToString([]byte{0x53, 0x49, 0x4e, 0x47, 0x41})
	legacyLowerHex := hex.EncodeToString([]byte{0x73, 0x69, 0x6e, 0x67, 0x61})
	if strings.Contains(lower, legacyUpperHex) || strings.Contains(lower, legacyLowerHex) {
		return fmt.Errorf("%q contains a hex-encoded legacy brand marker", declaredPath)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode %q for vector verification: %w", declaredPath, err)
	}
	return walkPublishedVectors(declaredPath, document)
}

func walkPublishedVectors(where string, node any) error {
	switch value := node.(type) {
	case map[string]any:
		if err := validatePublishedVector(where, value); err != nil {
			return err
		}
		for key, child := range value {
			if err := walkPublishedVectors(where+"."+key, child); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range value {
			if err := walkPublishedVectors(fmt.Sprintf("%s[%d]", where, index), child); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePublishedVector(where string, object map[string]any) error {
	if preimageHex, ok := object["preimage_hex"].(string); ok {
		preimage, err := decodePublishedHex(preimageHex)
		if err != nil {
			return fmt.Errorf("%s: invalid preimage_hex: %w", where, err)
		}
		for _, key := range []string{"digest_hex", "hash_hex", "evidence_digest_hex", "expected_hex"} {
			if digestHex, exists := object[key].(string); exists {
				digest := sha256.Sum256(preimage)
				if got := hex.EncodeToString(digest[:]); got != digestHex {
					return fmt.Errorf("%s: SHA-256(preimage_hex) is %s, want %s in %s", where, got, digestHex, key)
				}
			}
		}
	}
	domain, hasDomain := object["domain"].(string)
	if !hasDomain {
		return nil
	}
	framing, _ := object["framing"].(string)
	fields, hasFields := object["fields"].([]any)
	preimageHex, hasPreimage := object["preimage_hex"].(string)

	if err := validatePublishedTreeRoot(where, object, domain, framing); err != nil {
		return err
	}
	if err := validatePublishedMutations(where, object, domain); err != nil {
		return err
	}
	if hasPreimage && hasFields && typedFields(fields) && (framing == "" || framing == "H_FIELDS_V1") {
		preimage, err := encodeHFields(domain, fields)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if got := hex.EncodeToString(preimage); got != preimageHex {
			return fmt.Errorf("%s: typed fields reproduce preimage %s, want %s", where, got, preimageHex)
		}
		return validatePublishedDigest(where, object, preimage)
	}
	if framing == "H_V1" {
		payload, ok, err := publishedPayload(object)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		if !ok {
			return nil
		}
		preimage := encodeHV1(domain, payload)
		if hasPreimage && hex.EncodeToString(preimage) != preimageHex {
			return fmt.Errorf("%s: H_V1 payload does not reproduce preimage_hex", where)
		}
		return validatePublishedDigest(where, object, preimage)
	}
	return nil
}

func typedFields(fields []any) bool {
	return len(fields) == 0 || func() bool { _, ok := fields[0].(map[string]any); return ok }()
}

func encodeHFields(domain string, fields []any) ([]byte, error) {
	parts := make([][]byte, 0, len(fields)+1)
	parts = append(parts, []byte(domain))
	for index, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("field %d is not typed", index)
		}
		encoded, err := encodePublishedField(field)
		if err != nil {
			return nil, fmt.Errorf("field %d: %w", index, err)
		}
		parts = append(parts, encoded)
	}
	return encodeFrame(parts...), nil
}

func encodePublishedField(field map[string]any) ([]byte, error) {
	typeName, _ := field["type"].(string)
	switch typeName {
	case "bytes":
		if empty, _ := field["empty"].(bool); empty {
			return nil, nil
		}
		if _, present := field["hex"]; !present {
			return nil, nil
		}
		return decodePublishedHex(field["hex"])
	case "address":
		return decodePublishedHex(field["hex"])
	case "string":
		value, ok := field["utf8"].(string)
		if !ok {
			return nil, fmt.Errorf("string has no utf8 value")
		}
		return []byte(value), nil
	case "uint32", "enum":
		value, err := publishedUint(field["value"])
		if err != nil || value > uint64(^uint32(0)) {
			return nil, fmt.Errorf("invalid uint32/enum value")
		}
		return publishedU32(uint32(value)), nil
	case "uint64":
		value, err := publishedUint(field["value"])
		if err != nil {
			return nil, err
		}
		return publishedU64(value), nil
	case "int64":
		value, err := publishedInt(field["value"])
		if err != nil {
			return nil, err
		}
		return publishedU64(uint64(value)), nil
	case "bool":
		value, ok := field["bool"].(bool)
		if !ok {
			value, ok = field["value"].(bool)
		}
		if !ok {
			return nil, fmt.Errorf("bool has no value")
		}
		if value {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case "frame":
		fields, ok := field["fields"].([]any)
		if !ok {
			return nil, fmt.Errorf("frame has no fields")
		}
		parts := make([][]byte, 0, len(fields))
		for index, raw := range fields {
			nested, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("nested field %d is not typed", index)
			}
			encoded, err := encodePublishedField(nested)
			if err != nil {
				return nil, err
			}
			parts = append(parts, encoded)
		}
		return encodeFrame(parts...), nil
	case "optional":
		present, ok := field["present"].(bool)
		if !ok {
			return nil, fmt.Errorf("optional has no presence")
		}
		if !present {
			return []byte{0}, nil
		}
		fields, ok := field["fields"].([]any)
		if !ok || len(fields) != 1 {
			return nil, fmt.Errorf("present optional needs one field")
		}
		nested, ok := fields[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("optional value is not typed")
		}
		encoded, err := encodePublishedField(nested)
		if err != nil {
			return nil, err
		}
		return append([]byte{1}, encodeFrame(encoded)...), nil
	case "repeat":
		unit, err := decodePublishedHex(field["hex"])
		if err != nil {
			return nil, err
		}
		count, err := publishedUint(field["count"])
		if err != nil {
			return nil, err
		}
		return bytes.Repeat(unit, int(count)), nil
	case "":
		if empty, _ := field["empty"].(bool); empty {
			return nil, nil
		}
		if _, ok := field["hex"]; ok {
			return decodePublishedHex(field["hex"])
		}
		if value, ok := field["utf8"].(string); ok {
			return []byte(value), nil
		}
	}
	return nil, fmt.Errorf("unknown field type %q", typeName)
}

func publishedPayload(object map[string]any) ([]byte, bool, error) {
	if value, ok := object["payload_utf8"].(string); ok {
		return []byte(value), true, nil
	}
	if _, ok := object["payload_hex"]; ok {
		value, err := decodePublishedHex(object["payload_hex"])
		return value, true, err
	}
	if value, ok := object["payload"].(map[string]any); ok {
		encoded, err := encodePublishedField(value)
		return encoded, true, err
	}
	return nil, false, nil
}

func validatePublishedDigest(where string, object map[string]any, preimage []byte) error {
	digestHex, ok := object["digest_hex"].(string)
	if !ok {
		digestHex, ok = object["hash_hex"].(string)
	}
	if !ok {
		return nil
	}
	digest := sha256.Sum256(preimage)
	if got := hex.EncodeToString(digest[:]); got != digestHex {
		return fmt.Errorf("%s: SHA-256(preimage) is %s, want %s", where, got, digestHex)
	}
	return nil
}

func encodeHV1(domain string, payload []byte) []byte {
	out := append([]byte(nil), trueOpenFrameMagic...)
	out = append(out, publishedU32(uint32(len(domain)))...)
	out = append(out, domain...)
	out = append(out, publishedU64(uint64(len(payload)))...)
	return append(out, payload...)
}

func encodeFrame(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, publishedU64(uint64(len(part)))...)
		out = append(out, part...)
	}
	return out
}
func decodePublishedHex(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("missing hex value")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(decoded) != text {
		return nil, fmt.Errorf("non-canonical hex value")
	}
	return decoded, nil
}
func publishedUint(value any) (uint64, error) {
	switch typed := value.(type) {
	case json.Number:
		return strconv.ParseUint(typed.String(), 10, 64)
	case string:
		return strconv.ParseUint(typed, 10, 64)
	}
	return 0, fmt.Errorf("missing unsigned value")
}
func publishedInt(value any) (int64, error) {
	switch typed := value.(type) {
	case json.Number:
		return strconv.ParseInt(typed.String(), 10, 64)
	case string:
		return strconv.ParseInt(typed, 10, 64)
	}
	return 0, fmt.Errorf("missing signed value")
}
func publishedU32(value uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}
func publishedU64(value uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, value)
	return out
}
