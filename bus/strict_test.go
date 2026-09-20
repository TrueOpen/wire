package bus

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestPinnedTableMatchesProtoSources is what makes prototable.go a projection
// rather than a second, drifting definition of the wire format.
//
// The decoder cannot import generated code (keeper_api_contract.md §5.5), so
// the field numbers live in a hand-committed table. A table nobody checks is
// worse than no table: it would keep decoding confidently after a .proto changed
// underneath it, and a field the decoder does not know about is a field it
// rejects as unknown - so drift here turns valid envelopes into "malformed".
// This test re-derives every entry from the .proto sources and compares.
func TestPinnedTableMatchesProtoSources(t *testing.T) {
	sources := parseProtoSources(t, filepath.Join("..", "proto"))

	for name, pinned := range protoTables {
		actual, ok := sources[name]
		if !ok {
			t.Errorf("%s is pinned but no longer declared in proto/", name)
			continue
		}
		if len(pinned) != len(actual) {
			t.Errorf("%s: pinned %d fields, proto declares %d (pinned=%v proto=%v)",
				name, len(pinned), len(actual), numbers(pinned), numbers(actual))
		}
		for number, want := range actual {
			got, present := pinned[number]
			if !present {
				t.Errorf("%s field %d (%s) is declared in proto/ but missing from the pinned table",
					name, number, want.name)
				continue
			}
			if got.name != want.name {
				t.Errorf("%s field %d is pinned as %q but declared as %q", name, number, got.name, want.name)
			}
			if got.kind != want.kind {
				t.Errorf("%s.%s (field %d) is pinned as kind %d but declared as kind %d",
					name, want.name, number, got.kind, want.kind)
			}
			if got.repeated != want.repeated {
				t.Errorf("%s.%s (field %d) repeated is pinned as %v but declared as %v",
					name, want.name, number, got.repeated, want.repeated)
			}
			if want.kind == kindMessage && got.message != want.message {
				t.Errorf("%s.%s (field %d) is pinned as %s but declared as %s",
					name, want.name, number, got.message, want.message)
			}
		}
	}

	// The closure has to be complete in the other direction too: every message
	// type a pinned field references must itself be pinned, or the decoder would
	// reach a subtree it cannot check for unknown fields.
	for name, spec := range protoTables {
		for number, field := range spec {
			if field.kind != kindMessage {
				continue
			}
			if _, ok := protoTables[field.message]; !ok {
				t.Errorf("%s.%s (field %d) references %s, which has no pinned table",
					name, field.name, number, field.message)
			}
		}
	}
}

// declarationNoise matches the lines that legitimately appear inside a message
// body without declaring a field: reserved ranges, options, oneof and nested
// block openers and closers, comments and blanks. Anything else that survives is
// treated as a declaration the scanner failed to read.
var declarationNoise = regexp.MustCompile(`^\s*(?:reserved\b|option\b|oneof\b|enum\b|extend\b|extensions\b|//|/\*|\*|\}|\{|\)|\]|$)`)

func isDeclarationLike(line string) bool {
	if strings.TrimSpace(line) == "" || declarationNoise.MatchString(line) {
		return false
	}
	// A continuation of a field's option list - "[(cosmos_proto.scalar) = ..." on
	// its own line - is noise too, but a bare type-and-name with the number on the
	// next line is exactly what has to be caught.
	return !strings.HasPrefix(strings.TrimSpace(line), "[") && !strings.HasPrefix(strings.TrimSpace(line), "(")
}

func numbers(spec messageSpec) []int {
	out := make([]int, 0, len(spec))
	for number := range spec {
		out = append(out, int(number))
	}
	sort.Ints(out)
	return out
}

var (
	protoPackageLine = regexp.MustCompile(`^package\s+([^;\s]+)\s*;`)
	protoMessageLine = regexp.MustCompile(`^\s*message\s+(\w+)\s*\{`)
	protoOneofLine   = regexp.MustCompile(`^\s*oneof\s+\w+\s*\{`)
	protoFieldLine   = regexp.MustCompile(`^\s*(?:(repeated|optional)\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)`)
	protoEnumLine    = regexp.MustCompile(`^\s*enum\s+(\w+)\s*\{`)
)

var protoVarintTypes = map[string]struct{}{
	"int32": {}, "int64": {}, "uint32": {}, "uint64": {},
	"sint32": {}, "sint64": {}, "bool": {},
}

// parseProtoSources reads the field declarations out of proto/. It is a line
// scanner, not a protobuf parser: it only has to understand the subset this
// repository's .proto files actually use, and a real parser would mean a
// third-party dependency in the module the decoder lives in. If a file ever uses
// a construct it cannot read - a nested message, a group - the closure check
// above fails on the missing table rather than passing silently.
func parseProtoSources(t *testing.T, root string) map[string]messageSpec {
	t.Helper()

	type rawField struct {
		label, typeName, name string
		number                uint32
	}
	raw := map[string][]rawField{}
	enums := map[string]struct{}{}
	// unparsed records lines inside a message body that look like declarations but
	// that the scanner could not read. Silently skipping one is the failure mode
	// that would make this whole test worthless: the pinned table and the scanner
	// would both miss the same field, the comparison would pass, and the decoder
	// would reject that field as unknown at verification time. So they are
	// collected and reported instead.
	unparsed := map[string][]string{}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".proto" {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		var pkg, message string
		depth, oneofDepth := 0, 0
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if match := protoPackageLine.FindStringSubmatch(line); match != nil {
				pkg = match[1]
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if match := protoEnumLine.FindStringSubmatch(line); match != nil && depth == 0 {
				enums[pkg+"."+match[1]] = struct{}{}
				continue
			}
			if match := protoMessageLine.FindStringSubmatch(line); match != nil && depth == 0 {
				message = pkg + "." + match[1]
				if _, exists := raw[message]; !exists {
					raw[message] = nil
				}
				depth, oneofDepth = 1, 0
				continue
			}
			if message == "" {
				continue
			}
			openedNested := protoMessageLine.MatchString(line)
			openedOneof := protoOneofLine.MatchString(line)
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				message, depth, oneofDepth = "", 0, 0
				continue
			}
			if oneofDepth > 0 && depth < oneofDepth {
				oneofDepth = 0
				continue
			}
			if openedOneof && depth == 2 {
				oneofDepth = depth
				continue
			}
			// A nested message body would otherwise have its fields recorded under
			// the enclosing message, silently overwriting same-numbered entries and
			// turning this whole comparison into a false pass. A map field is
			// reported for the same reason: protoFieldLine cannot read it, so
			// letting it count as noise would hide it from both sides at once.
			if openedNested || (depth > 1 && depth != oneofDepth) {
				if isDeclarationLike(line) {
					unparsed[message] = append(unparsed[message], strings.TrimSpace(line))
				}
				continue
			}
			match := protoFieldLine.FindStringSubmatch(line)
			if match == nil {
				if isDeclarationLike(line) {
					unparsed[message] = append(unparsed[message], strings.TrimSpace(line))
				}
				continue
			}
			number, convErr := strconv.ParseUint(match[4], 10, 32)
			if convErr != nil {
				return fmt.Errorf("%s: field number %q: %w", path, match[4], convErr)
			}
			raw[message] = append(raw[message], rawField{
				label: match[1], typeName: match[2], name: match[3], number: uint32(number),
			})
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	resolve := func(typeName, pkg string) string {
		if _, ok := raw[typeName]; ok {
			return typeName
		}
		if _, ok := enums[typeName]; ok {
			return typeName
		}
		qualified := pkg + "." + typeName
		if _, ok := raw[qualified]; ok {
			return qualified
		}
		if _, ok := enums[qualified]; ok {
			return qualified
		}
		return ""
	}

	// Only the pinned messages are classified. The scanner reads the whole tree so
	// that a cross-file type reference resolves, but classifying every message in
	// the repository would make this test fail on a construct the scanner cannot
	// read in some unrelated file - a failure about the scanner, not about drift
	// in the table it exists to check.
	out := make(map[string]messageSpec, len(protoTables))
	for message := range protoTables {
		if lines := unparsed[message]; len(lines) > 0 {
			t.Errorf("%s contains %d line(s) the scanner could not read, so a field may be missing from both "+
				"the scan and the pinned table without this test noticing:\n  %s",
				message, len(lines), strings.Join(lines, "\n  "))
		}
		fields, ok := raw[message]
		if !ok {
			continue // reported as missing by the caller
		}
		pkg := message[:strings.LastIndex(message, ".")]
		spec := make(messageSpec, len(fields))
		for _, field := range fields {
			entry := fieldSpec{name: field.name, repeated: field.label == "repeated"}
			resolved := resolve(field.typeName, pkg)
			switch {
			case field.typeName == "string":
				entry.kind = kindString
			case field.typeName == "bytes":
				entry.kind = kindBytes
			default:
				if _, ok := protoVarintTypes[field.typeName]; ok {
					entry.kind = kindVarint
					break
				}
				if _, ok := enums[resolved]; resolved != "" && ok {
					entry.kind = kindVarint
					break
				}
				if _, ok := raw[resolved]; resolved != "" && ok {
					entry.kind = kindMessage
					entry.message = resolved
					break
				}
				t.Fatalf("%s.%s has type %q that the scanner cannot classify",
					message, field.name, field.typeName)
			}
			spec[field.number] = entry
		}
		out[message] = spec
	}
	return out
}

// TestStrictDecodeRejections covers the rules keeper_api_contract.md §5.5 step 1
// requires. Each case is a byte string a permissive decoder would accept, and
// each acceptance would let two implementations disagree about what was signed.
func TestStrictDecodeRejections(t *testing.T) {
	valid := mustHex(t, envelopeABytes)
	if _, err := DecodeEnvelope(valid); err != nil {
		t.Fatalf("the baseline envelope must decode for these mutations to mean anything: %v", err)
	}

	// tag(16, wireBytes) is field 16, which BusEnvelopeV1 does not declare.
	unknownField := append(bytes.Clone(valid), 0x82, 0x01, 0x00)
	// A second field 8 (message_id, singular string).
	duplicateSingular := append(bytes.Clone(valid), 0x42, 0x01, 'x')
	// Field 2 (chain_id, string) presented as a varint.
	wrongWireType := append(bytes.Clone(valid), 0x10, 0x01)
	// Field 1 with the retired start-group wire type.
	groupEncoding := append(bytes.Clone(valid), 0x0b)
	// Field number 0 is never valid.
	zeroFieldNumber := append(bytes.Clone(valid), 0x00, 0x00)
	// tag(1, wireBytes) is 0x0a. This is the same tag with bit 35 set, so it is a
	// minimally encoded varint that a uint32 conversion would fold back onto
	// field 1 - two spellings of one field, and so two payload digests for one
	// signed projection.
	foldedFieldNumber := append(bytes.Clone(valid), 0x8a, 0x80, 0x80, 0x80, 0x80, 0x01)
	// Field 3 (subject) with a length prefix that runs past the end of the input.
	// This one stands alone rather than being appended, because appending it after
	// a valid field 3 would be caught as a duplicate first.
	overlongLength := []byte{0x1a, 0x7f}

	for _, testCase := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"unknown field", unknownField, "unknown field"},
		{"duplicate singular field", duplicateSingular, "appears twice"},
		{"wrong wire type", wrongWireType, "wire type"},
		{"retired group encoding", groupEncoding, "group"},
		{"field number 0", zeroFieldNumber, "field number 0"},
		{"field number above the protobuf maximum", foldedFieldNumber, "above the"},
		{"length past the end of input", overlongLength, "remaining"},
		{"empty input", nil, "size must be"},
		{"truncated varint", []byte{0x08, 0xff}, "truncated"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodeEnvelope(testCase.raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

// TestVarintEncoding pins the canonicalization choice and its boundaries.
//
// Protobuf tolerates a padded varint, but tolerating one here would give two
// byte strings that decode to one envelope - and therefore two payload digests
// for one signed projection, which is precisely the ambiguity
// TRUEOPEN_BUS_PAYLOAD_V2 exists to remove by committing to exact bytes. A varint
// is non-minimal exactly when its terminating byte is zero and it is longer than
// one byte, so the legitimate single 0x00 and the illegitimate 0x80 0x00 sit one
// byte apart and both are covered here.
func TestVarintEncoding(t *testing.T) {
	for _, testCase := range []struct {
		name string
		raw  []byte
		want uint64
		ok   bool
	}{
		{"single zero", []byte{0x00}, 0, true},
		{"single one", []byte{0x01}, 1, true},
		{"one byte maximum", []byte{0x7f}, 127, true},
		{"minimal two bytes", []byte{0x80, 0x01}, 128, true},
		{"minimal 300", []byte{0xac, 0x02}, 300, true},
		{"maximum uint64", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, ^uint64(0), true},
		{"padded one", []byte{0x81, 0x00}, 0, false},
		{"padded zero in two bytes", []byte{0x80, 0x00}, 0, false},
		{"padded zero in three bytes", []byte{0x80, 0x80, 0x00}, 0, false},
		{"padded 128", []byte{0x80, 0x81, 0x00}, 0, false},
		{"overflows 64 bits", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, 0, false},
		{"longer than ten bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 0, false},
		{"truncated", []byte{0x80}, 0, false},
		{"empty", nil, 0, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, _, err := readVarint(testCase.raw)
			if testCase.ok {
				if err != nil {
					t.Fatalf("rejected a legitimate encoding: %v", err)
				}
				if got != testCase.want {
					t.Fatalf("decoded %d, want %d", got, testCase.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %x as %d", testCase.raw, got)
			}
		})
	}
}

// TestStrictDecodeRejectsUnknownFieldInsideThePayload confirms the rejection
// reaches the whole subtree. The envelope is well-formed and field 14 is
// recomputed so the payload commitment still holds - otherwise the digest check
// would reject first and this would prove nothing about payload strictness.
func TestStrictDecodeRejectsUnknownFieldInsideThePayload(t *testing.T) {
	raw := mustHex(t, envelopeABytes)
	envelope, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}

	// OpenVerifyV1 declares fields 1..8; add field 9 as a varint.
	tamperedPayload := append(bytes.Clone(envelope.Payload), 0x48, 0x01)
	rebuilt := reencodeWithPayload(t, raw, envelope.Payload, tamperedPayload)
	rebuilt = replacePayloadDigest(t, rebuilt, envelope.Fields.PayloadDigest, tamperedPayload)

	_, err = DecodeEnvelope(rebuilt)
	if err == nil {
		t.Fatal("an unknown field inside the payload was accepted")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// replacePayloadDigest rewrites field 14 to commit to newPayload. Field 14 is
// always raw32, so the length prefix does not change.
func replacePayloadDigest(t *testing.T, raw, oldDigest, newPayload []byte) []byte {
	t.Helper()
	prefix := encodeBytesField(14, oldDigest)
	index := bytes.Index(raw, prefix)
	if index < 0 {
		t.Fatal("field 14 was not found inside the encoded envelope")
	}
	digest := PayloadDigest(newPayload)
	out := bytes.Clone(raw)
	copy(out[index:], encodeBytesField(14, digest[:]))
	return out
}

// TestDecodeRejectsPayloadDigestMismatch covers the case where field 14 does not
// commit to field 13. The signature covers field 14, so if the two disagree the
// bytes on the wire are not the bytes that were signed.
func TestDecodeRejectsPayloadDigestMismatch(t *testing.T) {
	raw := mustHex(t, envelopeABytes)
	envelope, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one byte of the payload without touching field 14.
	tampered := bytes.Clone(envelope.Payload)
	tampered[len(tampered)-1] ^= 1
	rebuilt := reencodeWithPayload(t, raw, envelope.Payload, tampered)

	_, err = DecodeEnvelope(rebuilt)
	if err == nil {
		t.Fatal("a payload that does not match payload_digest was accepted")
	}
	if !strings.Contains(err.Error(), "payload_digest") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// reencodeWithPayload substitutes one payload for another inside the encoded
// envelope, rewriting field 13's length prefix so the result is still parseable
// and the only thing under test is the field content.
func reencodeWithPayload(t *testing.T, raw, oldPayload, newPayload []byte) []byte {
	t.Helper()
	prefix := encodeBytesField(13, oldPayload)
	index := bytes.Index(raw, prefix)
	if index < 0 {
		t.Fatal("field 13 was not found inside the encoded envelope")
	}
	out := make([]byte, 0, len(raw)+len(newPayload))
	out = append(out, raw[:index]...)
	out = append(out, encodeBytesField(13, newPayload)...)
	out = append(out, raw[index+len(prefix):]...)
	return out
}

func encodeBytesField(number uint32, value []byte) []byte {
	out := appendVarint(nil, uint64(number)<<3|wireBytes)
	out = appendVarint(out, uint64(len(value)))
	return append(out, value...)
}

func appendVarint(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

// TestDecodeRejectsKindPayloadTypeMismatch covers the frozen mapping. A kind
// paired with another kind's payload_type would let a sender route a message the
// permission matrix does not allow it to send.
func TestDecodeRejectsKindPayloadTypeMismatch(t *testing.T) {
	scope, _, err := projectScope(KindOpenVerify, PayloadTypeVerifyResultV1, []byte{0x00})
	if err == nil {
		t.Fatalf("a mismatched kind/payload_type pair was accepted: %+v", scope)
	}
	if !strings.Contains(err.Error(), "requires payload_type") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
	if _, _, err := projectScope(99, 99, []byte{0x00}); err == nil {
		t.Fatal("an unknown kind was accepted")
	}
}

// TestSubjectTemplatesCoverEveryKind guards against a kind gaining a projection
// without a subject template, which would leave ExpectedSubject empty and make
// the subject comparison in VerifyEvidenceEnvelope trivially satisfiable by an
// envelope whose signed subject was also empty.
func TestSubjectTemplatesCoverEveryKind(t *testing.T) {
	for kind := range kindPayloadType {
		prefix := subjectPrefixForKind(t, kind)
		if prefix == "" {
			t.Errorf("kind %d has no subject prefix", kind)
			continue
		}
		if !strings.HasPrefix(prefix, "trueopen.") || !strings.HasSuffix(prefix, ".") {
			t.Errorf("kind %d subject prefix %q is not a trueopen.* template", kind, prefix)
		}
	}
}

func subjectPrefixForKind(t *testing.T, kind int32) string {
	t.Helper()
	switch kind {
	case KindOrderBroadcast:
		return subjectTaskOpenPrefix
	case KindWorkerHandraise:
		return subjectWorkerHandraisePrefix
	case KindWorkerAssignmentNotify:
		return subjectWorkerAssignmentPrefix
	case KindOutputAvailable:
		return subjectOutputAvailablePrefix
	case KindOpenVerify:
		return subjectOpenVerifyPrefix
	case KindVerifierHandraise:
		return subjectVerifierHandraisePrefix
	case KindVerifierAssignmentNotify:
		return subjectVerifierAssignmentPrefix
	case KindVerifyResult:
		return subjectVerifyResultPrefix
	default:
		return ""
	}
}

// TestEnvelopeBPayloadDigest keeps the second golden envelope's payload
// commitment asserted too: the pair only proves equivocation handling if both
// halves are pinned, not just the one the other tests read most.
func TestEnvelopeBPayloadDigest(t *testing.T) {
	envelope, err := DecodeEnvelope(mustHex(t, envelopeBBytes))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelope.Fields.PayloadDigest); got != envelopeBPayloadDigest {
		t.Fatalf("envelope_b payload_digest %s, want %s", got, envelopeBPayloadDigest)
	}
	if got := PayloadDigest(envelope.Payload); hex.EncodeToString(got[:]) != envelopeBPayloadDigest {
		t.Fatalf("recomputed envelope_b payload digest %x", got)
	}
}

// TestIsDeclarationLike checks the guard that keeps the drift test honest. The
// case that matters is the last one: a field whose number sits on the following
// line is invisible to protoFieldLine, and if it were also treated as noise the
// scan and the pinned table would agree about a field neither one saw.
func TestIsDeclarationLike(t *testing.T) {
	for _, testCase := range []struct {
		name string
		line string
		want bool
	}{
		{"blank", "", false},
		{"comment", "  // a comment", false},
		{"reserved", "  reserved 4;", false},
		{"reserved range", "  reserved 4 to 7;", false},
		{"option", `  option (amino.name) = "x";`, false},
		{"oneof opener", "  oneof evidence {", false},
		{"closing brace", "  }", false},
		{"option continuation", `    [(cosmos_proto.scalar) = "cosmos.AddressString"];`, false},
		{"paren continuation", "    (gogoproto.nullable) = false];", false},
		{"field split across lines", "  bytes task_id", true},
		{"unreadable construct", "  group Legacy = 9 {", true},
		// A map field and a nested message opener are both reported rather than
		// treated as noise. protoFieldLine cannot read either, so letting them pass
		// would hide a field from the scan and from the pinned table at the same
		// time - and the decoder would then reject that field as unknown.
		{"map field", "  map<string, string> labels = 12;", true},
		{"nested message", "  message Inner {", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := isDeclarationLike(testCase.line); got != testCase.want {
				t.Fatalf("isDeclarationLike(%q) = %v, want %v", testCase.line, got, testCase.want)
			}
		})
	}

	// And a normal field line is read by protoFieldLine, so it never reaches the
	// guard at all - confirmed here so the two are not independently plausible.
	if protoFieldLine.FindStringSubmatch("  bytes task_id = 1;") == nil {
		t.Fatal("protoFieldLine no longer reads an ordinary field declaration")
	}
	if protoFieldLine.FindStringSubmatch(`  string addr = 6 [(cosmos_proto.scalar) = "cosmos.AddressString"];`) == nil {
		t.Fatal("protoFieldLine no longer reads a field declaration with options")
	}
}
