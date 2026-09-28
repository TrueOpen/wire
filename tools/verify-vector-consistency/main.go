// Command verify-vector-consistency recomputes what a fixture file states about
// itself instead of trusting it. Three kinds of self-description drift silently
// when a vector is edited, because nothing downstream of the edit reads them:
//
//   - leaf_accounting, the scalar/submessage/repeated counts a parameter vector
//     publishes for its message tree;
//   - the digest of every tamper and replay row, which is a mutation of the base
//     vector and has to move whenever the base's encoding moves;
//   - vector names, which consumers use to select a vector and which only work
//     as a key if no two vectors in a file share one.
//
// Base preimages are recomputed too, so a row is always checked against a base
// that is itself known to be right.
//
// Usage:
//
//	verify-vector-consistency -root ../testdata/v1
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func main() {
	root := flag.String("root", "../testdata/v1", "fixture directory to verify")
	flag.Parse()

	report, err := verifyRoot(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("verified %d file(s): %d base digest(s), %d tamper row(s), %d replay row(s), %d leaf_accounting block(s), %d descriptive row(s) not recomputable\n",
		report.files, report.bases, report.tampers, report.replays, report.accounting, report.descriptive)
}

// report counts what was checked, so a run that silently checks nothing is
// visible in the CI log.
type report struct {
	files, bases, tampers, replays, accounting, descriptive int
}

// verifyRoot checks every fixture file under root (the fixture manifest itself
// is not a fixture) and returns every problem found, not just the first, so a
// single run lists everything a release has to fix.
func verifyRoot(root string) (report, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".json" && entry.Name() != "manifest.json" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return report{}, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return report{}, fmt.Errorf("no fixture files under %s", root)
	}

	var total report
	var problems []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return report{}, err
		}
		name, _ := filepath.Rel(root, path)
		got, errs := verifyFile(filepath.ToSlash(name), raw)
		total.files++
		total.bases += got.bases
		total.tampers += got.tampers
		total.replays += got.replays
		total.accounting += got.accounting
		total.descriptive += got.descriptive
		problems = append(problems, errs...)
	}
	if len(problems) != 0 {
		return total, fmt.Errorf("%d vector self-consistency problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return total, nil
}

// verifyFile runs every check over one fixture document.
func verifyFile(name string, raw []byte) (report, []string) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return report{}, []string{fmt.Sprintf("%s: decode: %v", name, err)}
	}
	checker := &fileChecker{name: name, rpcDigests: map[string]string{}}
	checker.collectRPCDigests(document)
	checker.checkNames(document)
	checker.walk(name, document)
	return checker.report, checker.problems
}

type fileChecker struct {
	name     string
	report   report
	problems []string
	// rpcDigests maps an RPC method literal to its TRUEOPEN_QUERY_RPC_V1 digest,
	// as published by the RPC vectors of the same file. A selector replay row that
	// substitutes another RPC names the method, and the row's preimage frames that
	// method's digest.
	rpcDigests map[string]string
}

func (c *fileChecker) fail(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

func (c *fileChecker) collectRPCDigests(node any) {
	switch value := node.(type) {
	case map[string]any:
		method, hasMethod := value["rpc_method"].(string)
		digest, hasDigest := value["digest_hex"].(string)
		if value["domain"] == "TRUEOPEN_QUERY_RPC_V1" && hasMethod && hasDigest {
			c.rpcDigests[method] = digest
		}
		for _, child := range value {
			c.collectRPCDigests(child)
		}
	case []any:
		for _, child := range value {
			c.collectRPCDigests(child)
		}
	}
}

// checkNames requires the name of every entry of a top-level vector list to be
// unique within the file. Consumers select a vector by name; a duplicated name
// makes that selection depend on array order.
func (c *fileChecker) checkNames(document any) {
	object, ok := document.(map[string]any)
	if !ok {
		return
	}
	for _, list := range []string{"vectors", "cases"} {
		entries, ok := object[list].([]any)
		if !ok {
			continue
		}
		seen := map[string]int{}
		for index, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			// Positional lists (the MMR cases are keyed by leaf_count) carry no
			// names; only a name that is present is a selection key.
			name, ok := entry["name"].(string)
			if !ok {
				continue
			}
			if first, exists := seen[name]; exists {
				c.fail("%s: %s[%d] reuses the name %q of %s[%d]", c.name, list, index, name, list, first)
				continue
			}
			seen[name] = index
		}
	}
}

func (c *fileChecker) walk(where string, node any) {
	switch value := node.(type) {
	case map[string]any:
		c.checkObject(where, value)
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			c.walk(where+"."+key, value[key])
		}
	case []any:
		for index, child := range value {
			label := fmt.Sprintf("%s[%d]", where, index)
			if object, ok := child.(map[string]any); ok {
				if name, ok := object["name"].(string); ok {
					label = fmt.Sprintf("%s[%s]", where, name)
				}
			}
			c.walk(label, child)
		}
	}
}

// checkObject handles one JSON object. Anything carrying leaf_accounting has
// its counts recomputed; anything carrying a domain and typed H_FIELDS_V1
// fields is a base vector whose preimage, digest and mutation rows are
// recomputed.
func (c *fileChecker) checkObject(where string, object map[string]any) {
	if accounting, ok := object["leaf_accounting"]; ok {
		c.report.accounting++
		c.checkLeafAccounting(where, object, accounting)
	}

	domain, hasDomain := object["domain"].(string)
	fields, hasFields := object["fields"].([]any)
	framing, _ := object["framing"].(string)
	typed := hasFields && len(fields) != 0
	if typed {
		_, typed = fields[0].(map[string]any)
	}
	if !hasDomain || !typed || (framing != "" && framing != "H_FIELDS_V1") {
		// Rows under anything that is not a typed H_FIELDS_V1 vector cannot be
		// recomputed here. They must not exist, rather than be skipped quietly.
		for _, key := range []string{"tamper", "replay"} {
			for _, row := range rows(object, key) {
				if isDescriptive(row) {
					c.report.descriptive++
					continue
				}
				if _, ok := row["digest_hex"]; ok {
					c.fail("%s: %s %q has a digest but its vector has no typed H_FIELDS_V1 fields to recompute it from", where, key, rowName(row))
				}
			}
		}
		return
	}

	parts, err := encodeFields(fields)
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	c.checkBase(where, object, domain, parts)
	for _, row := range rows(object, "tamper") {
		if isDescriptive(row) {
			c.report.descriptive++
			continue
		}
		c.report.tampers++
		c.checkTamper(where, domain, parts, row)
	}
	for _, row := range rows(object, "replay") {
		c.report.replays++
		c.checkReplay(where, domain, fields, parts, row)
	}
}

// checkBase requires the typed fields to reproduce preimage_hex and the
// preimage to hash to digest_hex, whichever of the two the vector publishes.
func (c *fileChecker) checkBase(where string, object map[string]any, domain string, parts [][]byte) {
	preimage := hFields(domain, parts)
	checked := false
	if published, ok := object["preimage_hex"].(string); ok {
		checked = true
		if got := hex.EncodeToString(preimage); got != published {
			c.fail("%s: fields reproduce preimage %s, the vector publishes %s", where, abbreviate(got), abbreviate(published))
		}
	}
	if published, ok := object["digest_hex"].(string); ok {
		checked = true
		if got := digestHex(preimage); got != published {
			c.fail("%s: fields hash to %s, the vector publishes %s", where, got, published)
		}
	}
	if checked {
		c.report.bases++
	}
}

// checkTamper recomputes a single-bit tamper row: bit `bit` (0 is the least
// significant) of byte `byte` of the encoded top-level field `field` is flipped.
// A negative byte counts from the end of the field, so -1 is its last byte.
func (c *fileChecker) checkTamper(where, domain string, parts [][]byte, row map[string]any) {
	fieldIndex, errField := intValue(row["field"])
	byteIndex, errByte := intValue(row["byte"])
	bit, errBit := intValue(row["bit"])
	published, hasDigest := row["digest_hex"].(string)
	if errField != nil || errByte != nil || errBit != nil || !hasDigest {
		c.fail("%s: tamper %q needs field, byte, bit and digest_hex", where, rowName(row))
		return
	}
	if fieldIndex < 0 || fieldIndex >= len(parts) {
		c.fail("%s: tamper %q names field %d, the vector has %d", where, rowName(row), fieldIndex, len(parts))
		return
	}
	if byteIndex < 0 {
		byteIndex += len(parts[fieldIndex])
	}
	if byteIndex < 0 || byteIndex >= len(parts[fieldIndex]) || bit < 0 || bit > 7 {
		c.fail("%s: tamper %q points outside field %d", where, rowName(row), fieldIndex)
		return
	}
	mutated := cloneParts(parts)
	mutated[fieldIndex][byteIndex] ^= 1 << bit
	c.compareRow(where, "tamper", row, published, hFields(domain, mutated))
}

// checkReplay recomputes a replay row. Three shapes exist:
//
//   - overrides: [{field, value}] replaces top-level fields by index with fully
//     typed fields;
//   - field + value: replaces one top-level field with a bare value, typed like
//     the field it replaces (an RPC method for rpc_method_digest, which frames
//     that method's published TRUEOPEN_QUERY_RPC_V1 digest);
//   - any other key naming a top-level field (chain_id, params_version) replaces
//     that field's value.
func (c *fileChecker) checkReplay(where, domain string, fields []any, parts [][]byte, row map[string]any) {
	published, ok := row["digest_hex"].(string)
	if !ok {
		c.fail("%s: replay %q has no digest_hex", where, rowName(row))
		return
	}
	mutated := cloneParts(parts)
	replace := func(index int, value any) error {
		if index < 0 || index >= len(fields) {
			return fmt.Errorf("field %d does not exist", index)
		}
		target, _ := fields[index].(map[string]any)
		encoded, err := c.encodeBareValue(target, value)
		if err != nil {
			return err
		}
		mutated[index] = encoded
		return nil
	}

	var err error
	switch {
	case row["overrides"] != nil:
		overrides, _ := row["overrides"].([]any)
		if len(overrides) == 0 {
			err = errors.New("overrides is empty")
		}
		for _, raw := range overrides {
			override, _ := raw.(map[string]any)
			index, indexErr := intValue(override["field"])
			value, _ := override["value"].(map[string]any)
			if indexErr != nil || value == nil || index < 0 || index >= len(mutated) {
				err = errors.New("override needs a field index and a typed value")
				break
			}
			if mutated[index], err = encodeField(value); err != nil {
				break
			}
		}
	case row["field"] != nil:
		index, indexErr := intValue(row["field"])
		if indexErr != nil {
			err = indexErr
			break
		}
		err = replace(index, row["value"])
	default:
		replaced := 0
		for key, value := range row {
			if key == "digest_hex" || key == "name" || key == "reason" {
				continue
			}
			index := fieldIndexByName(fields, key)
			if index < 0 {
				err = fmt.Errorf("key %q names no top-level field", key)
				break
			}
			if err = replace(index, value); err != nil {
				break
			}
			replaced++
		}
		if err == nil && replaced == 0 {
			err = errors.New("replay names no field to replace")
		}
	}
	if err != nil {
		c.fail("%s: replay %q: %v", where, rowName(row), err)
		return
	}
	c.compareRow(where, "replay", row, published, hFields(domain, mutated))
}

func (c *fileChecker) compareRow(where, kind string, row map[string]any, published string, preimage []byte) {
	if got := digestHex(preimage); got != published {
		c.fail("%s: %s %q recomputes to %s, the row publishes %s", where, kind, rowName(row), got, published)
	}
}

// encodeBareValue encodes a replay value that carries no type of its own, using
// the type of the field it replaces.
func (c *fileChecker) encodeBareValue(target map[string]any, value any) ([]byte, error) {
	if target == nil {
		return nil, errors.New("replaced field is not typed")
	}
	if target["name"] == "rpc_method_digest" {
		method, ok := value.(string)
		digest, known := c.rpcDigests[method]
		if !ok || !known {
			return nil, fmt.Errorf("no TRUEOPEN_QUERY_RPC_V1 vector in this file for %v", value)
		}
		return hex.DecodeString(digest)
	}
	typed := map[string]any{"type": target["type"]}
	switch target["type"] {
	case "string":
		typed["utf8"] = value
	case "bytes", "address":
		typed["hex"] = value
	case "bool":
		typed["bool"] = value
	default:
		typed["value"] = value
	}
	return encodeField(typed)
}

// isDescriptive reports a row that states its change in prose ("change") rather
// than as a field/byte/bit or a replacement value. Such a row cannot be
// recomputed; it is counted so the CI log shows how many there are.
func isDescriptive(row map[string]any) bool {
	_, hasChange := row["change"].(string)
	_, hasField := row["field"]
	return hasChange && !hasField
}

// checkLeafAccounting recomputes {scalars, submessages, repeated} over the
// message tree, which is the vector's single top-level frame field (the fields
// around it, such as chain_id and params_version, scope the commitment and are
// not part of the message). Walking that tree:
//
//   - a non-frame field is a scalar;
//   - a frame whose first child is element_count is a repeated field: it counts
//     once as repeated, and element_count itself is not a scalar;
//   - any other frame is a submessage; the root frame is not counted.
func (c *fileChecker) checkLeafAccounting(where string, object map[string]any, raw any) {
	published, ok := raw.(map[string]any)
	if !ok {
		c.fail("%s: leaf_accounting is not an object", where)
		return
	}
	fields, _ := object["fields"].([]any)
	var root map[string]any
	for _, candidate := range fields {
		field, _ := candidate.(map[string]any)
		if field != nil && field["type"] == "frame" {
			if root != nil {
				c.fail("%s: leaf_accounting needs exactly one top-level frame to count", where)
				return
			}
			root = field
		}
	}
	if root == nil {
		c.fail("%s: leaf_accounting has no top-level frame to count", where)
		return
	}
	var counts struct{ scalars, submessages, repeated int }
	var visit func(field map[string]any)
	visit = func(field map[string]any) {
		if field["type"] != "frame" {
			counts.scalars++
			return
		}
		children, _ := field["fields"].([]any)
		if len(children) != 0 {
			if first, _ := children[0].(map[string]any); first != nil && first["name"] == "element_count" {
				counts.repeated++
				children = children[1:]
			} else {
				counts.submessages++
			}
		} else {
			counts.submessages++
		}
		for _, child := range children {
			if nested, ok := child.(map[string]any); ok {
				visit(nested)
			}
		}
	}
	children, _ := root["fields"].([]any)
	for _, child := range children {
		if nested, ok := child.(map[string]any); ok {
			visit(nested)
		}
	}
	want := []struct {
		key   string
		value int
	}{{"scalars", counts.scalars}, {"submessages", counts.submessages}, {"repeated", counts.repeated}}
	for _, expected := range want {
		key, value := expected.key, expected.value
		got, err := intValue(published[key])
		if err != nil {
			c.fail("%s: leaf_accounting.%s is missing", where, key)
			continue
		}
		if got != value {
			c.fail("%s: leaf_accounting.%s is %d, the field tree has %d", where, key, got, value)
		}
	}
	if len(published) != len(want) {
		c.fail("%s: leaf_accounting must carry exactly scalars, submessages and repeated", where)
	}
}

// --- H_FIELDS_V1 encoding -------------------------------------------------

// hFields is FRAME_V1(domain, field...): each part prefixed by u64be(len).
func hFields(domain string, parts [][]byte) []byte {
	return frame(append([][]byte{[]byte(domain)}, parts...)...)
}

func frame(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = binary.BigEndian.AppendUint64(out, uint64(len(part)))
		out = append(out, part...)
	}
	return out
}

func encodeFields(fields []any) ([][]byte, error) {
	parts := make([][]byte, 0, len(fields))
	for index, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("field %d is not typed", index)
		}
		encoded, err := encodeField(field)
		if err != nil {
			return nil, fmt.Errorf("field %d (%v): %w", index, field["name"], err)
		}
		parts = append(parts, encoded)
	}
	return parts, nil
}

// encodeField encodes one typed field as the fixtures spell it.
func encodeField(field map[string]any) ([]byte, error) {
	switch field["type"] {
	case "string":
		value, ok := field["utf8"].(string)
		if !ok {
			return nil, errors.New("string has no utf8 value")
		}
		return []byte(value), nil
	case "bytes", "address":
		if empty, _ := field["empty"].(bool); empty {
			return nil, nil
		}
		if _, present := field["hex"]; !present && field["type"] == "bytes" {
			return nil, nil
		}
		return canonicalHex(field["hex"])
	case "uint32", "enum":
		value, err := uintValue(field["value"])
		if err != nil || value > math.MaxUint32 {
			return nil, errors.New("invalid uint32 value")
		}
		return binary.BigEndian.AppendUint32(nil, uint32(value)), nil
	case "uint64":
		value, err := uintValue(field["value"])
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint64(nil, value), nil
	case "int32":
		value, err := intValue(field["value"])
		if err != nil || value < math.MinInt32 || value > math.MaxInt32 {
			return nil, errors.New("invalid int32 value")
		}
		return binary.BigEndian.AppendUint32(nil, uint32(int32(value))), nil
	case "int64":
		value, err := intValue(field["value"])
		if err != nil {
			return nil, err
		}
		return binary.BigEndian.AppendUint64(nil, uint64(int64(value))), nil
	case "bool":
		value, ok := field["bool"].(bool)
		if !ok {
			value, ok = field["value"].(bool)
		}
		if !ok {
			return nil, errors.New("bool has no value")
		}
		if value {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case "frame":
		children, ok := field["fields"].([]any)
		if !ok {
			return nil, errors.New("frame has no fields")
		}
		parts, err := encodeFields(children)
		if err != nil {
			return nil, err
		}
		return frame(parts...), nil
	case "optional":
		present, ok := field["present"].(bool)
		if !ok {
			return nil, errors.New("optional has no presence")
		}
		if !present {
			return []byte{0}, nil
		}
		children, _ := field["fields"].([]any)
		if len(children) != 1 {
			return nil, errors.New("present optional needs exactly one field")
		}
		parts, err := encodeFields(children)
		if err != nil {
			return nil, err
		}
		return append([]byte{1}, frame(parts...)...), nil
	case "repeat":
		unit, err := canonicalHex(field["hex"])
		if err != nil {
			return nil, err
		}
		count, err := uintValue(field["count"])
		if err != nil || count > 1<<20 {
			return nil, errors.New("invalid repeat count")
		}
		return bytes.Repeat(unit, int(count)), nil
	}
	return nil, fmt.Errorf("unknown field type %v", field["type"])
}

// --- helpers --------------------------------------------------------------

func rows(object map[string]any, key string) []map[string]any {
	raw, _ := object[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, value := range raw {
		if row, ok := value.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}

func rowName(row map[string]any) string {
	if name, ok := row["name"].(string); ok {
		return name
	}
	return "?"
}

func fieldIndexByName(fields []any, name string) int {
	for index, raw := range fields {
		if field, ok := raw.(map[string]any); ok && field["name"] == name {
			return index
		}
	}
	return -1
}

func cloneParts(parts [][]byte) [][]byte {
	out := make([][]byte, len(parts))
	for index, part := range parts {
		out[index] = append([]byte(nil), part...)
	}
	return out
}

func digestHex(preimage []byte) string {
	digest := sha256.Sum256(preimage)
	return hex.EncodeToString(digest[:])
}

// canonicalHex accepts only lowercase, even-length hex, the one spelling the
// fixtures use.
func canonicalHex(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, errors.New("missing hex value")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(decoded) != text {
		return nil, fmt.Errorf("non-canonical hex %q", abbreviate(text))
	}
	return decoded, nil
}

func uintValue(value any) (uint64, error) {
	switch typed := value.(type) {
	case json.Number:
		return strconv.ParseUint(typed.String(), 10, 64)
	case string:
		return strconv.ParseUint(typed, 10, 64)
	}
	return 0, errors.New("missing unsigned value")
}

func intValue(value any) (int, error) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(typed.String(), 10, 64)
		return int(parsed), err
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		return int(parsed), err
	}
	return 0, errors.New("missing integer value")
}

func abbreviate(text string) string {
	if len(text) <= 24 {
		return text
	}
	return text[:24] + "…"
}
