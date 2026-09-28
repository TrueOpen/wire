package eip712

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Field is one member of an EIP-712 struct type.
type Field struct {
	Type string
	Name string
}

// Types maps a struct type name to its members in declaration order.
type Types map[string][]Field

var structPattern = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\(([^()]*)\)`)

// ParseEncodeType reads an encodeType string, which is the primary type
// followed by its dependencies, into Types, and returns the primary type name.
// It accepts only the exact single-line form: members separated by one comma,
// one space between type and name, and nothing between struct definitions.
func ParseEncodeType(encoded string) (string, Types, error) {
	types := Types{}
	primary := ""
	rest := encoded
	for rest != "" {
		match := structPattern.FindStringSubmatchIndex(rest)
		if match == nil || match[0] != 0 {
			return "", nil, fmt.Errorf("encodeType %q is not a sequence of Name(members)", encoded)
		}
		name := rest[match[2]:match[3]]
		body := rest[match[4]:match[5]]
		if _, exists := types[name]; exists {
			return "", nil, fmt.Errorf("encodeType defines %s twice", name)
		}
		var fields []Field
		if body != "" {
			for _, member := range strings.Split(body, ",") {
				parts := strings.Split(member, " ")
				if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
					return "", nil, fmt.Errorf("member %q of %s is not \"type name\"", member, name)
				}
				fields = append(fields, Field{Type: parts[0], Name: parts[1]})
			}
		}
		types[name] = fields
		if primary == "" {
			primary = name
		}
		rest = rest[match[1]:]
	}
	if primary == "" {
		return "", nil, errors.New("empty encodeType")
	}
	// Re-encoding must give back the input, which checks the dependency order.
	if again := types.EncodeType(primary); again != encoded {
		return "", nil, fmt.Errorf("encodeType %q is not canonical; EIP-712 orders it %q", encoded, again)
	}
	return primary, types, nil
}

// ParseTypeGraph reads struct definitions listed one per entry, the first
// being the primary type, in any dependency order.
func ParseTypeGraph(definitions []string) (string, Types, error) {
	types := Types{}
	primary := ""
	for _, definition := range definitions {
		name, parsed, err := parseOne(definition)
		if err != nil {
			return "", nil, err
		}
		if _, exists := types[name]; exists {
			return "", nil, fmt.Errorf("type graph defines %s twice", name)
		}
		types[name] = parsed
		if primary == "" {
			primary = name
		}
	}
	return primary, types, nil
}

func parseOne(definition string) (string, []Field, error) {
	match := structPattern.FindStringSubmatchIndex(definition)
	if match == nil || match[0] != 0 || match[1] != len(definition) {
		return "", nil, fmt.Errorf("%q is not Name(members)", definition)
	}
	name := definition[match[2]:match[3]]
	var fields []Field
	for _, member := range strings.Split(definition[match[4]:match[5]], ",") {
		parts := strings.Split(member, " ")
		if len(parts) != 2 {
			return "", nil, fmt.Errorf("member %q of %s is not \"type name\"", member, name)
		}
		fields = append(fields, Field{Type: parts[0], Name: parts[1]})
	}
	return name, fields, nil
}

func baseType(typ string) string {
	return strings.TrimSuffix(typ, "[]")
}

// dependencies collects every struct type reachable from name, name included.
func (t Types) dependencies(name string, found map[string]bool) {
	if found[name] {
		return
	}
	if _, isStruct := t[name]; !isStruct {
		return
	}
	found[name] = true
	for _, field := range t[name] {
		t.dependencies(baseType(field.Type), found)
	}
}

// EncodeType is the primary type's definition followed by every dependency's,
// the dependencies sorted by name.
func (t Types) EncodeType(primary string) string {
	found := map[string]bool{}
	t.dependencies(primary, found)
	delete(found, primary)
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range append([]string{primary}, names...) {
		members := make([]string, 0, len(t[name]))
		for _, field := range t[name] {
			members = append(members, field.Type+" "+field.Name)
		}
		out.WriteString(name + "(" + strings.Join(members, ",") + ")")
	}
	return out.String()
}

// TypeHash is keccak256 of the encodeType string.
func (t Types) TypeHash(primary string) [32]byte {
	return Keccak256([]byte(t.EncodeType(primary)))
}

// HashStruct is keccak256(typeHash || encodeData(message)). Every member must be
// present in message and message must carry no other key.
func (t Types) HashStruct(primary string, message map[string]any) ([32]byte, error) {
	fields, ok := t[primary]
	if !ok {
		return [32]byte{}, fmt.Errorf("unknown struct type %s", primary)
	}
	if len(message) != len(fields) {
		return [32]byte{}, fmt.Errorf("%s has %d members, the message has %d keys", primary, len(fields), len(message))
	}
	typeHash := t.TypeHash(primary)
	encoded := append([]byte(nil), typeHash[:]...)
	for _, field := range fields {
		value, present := message[field.Name]
		if !present {
			return [32]byte{}, fmt.Errorf("%s.%s is missing", primary, field.Name)
		}
		word, err := t.encodeValue(field.Type, value)
		if err != nil {
			return [32]byte{}, fmt.Errorf("%s.%s: %w", primary, field.Name, err)
		}
		encoded = append(encoded, word[:]...)
	}
	return Keccak256(encoded), nil
}

// encodeValue encodes one member as its 32-byte word. Values are spelled the
// way the fixtures spell them: integers as decimal strings, byte strings and
// addresses as lowercase hex without a prefix, strings as themselves.
func (t Types) encodeValue(typ string, value any) ([32]byte, error) {
	var word [32]byte
	if strings.HasSuffix(typ, "[]") {
		items, ok := value.([]any)
		if !ok {
			return word, fmt.Errorf("%s value is not an array", typ)
		}
		var concatenated []byte
		for index, item := range items {
			element, err := t.encodeValue(baseType(typ), item)
			if err != nil {
				return word, fmt.Errorf("[%d]: %w", index, err)
			}
			concatenated = append(concatenated, element[:]...)
		}
		return Keccak256(concatenated), nil
	}
	if _, isStruct := t[typ]; isStruct {
		object, ok := value.(map[string]any)
		if !ok {
			return word, fmt.Errorf("%s value is not an object", typ)
		}
		return t.HashStruct(typ, object)
	}
	switch {
	case typ == "string":
		text, ok := value.(string)
		if !ok {
			return word, errors.New("string value is not a string")
		}
		return Keccak256([]byte(text)), nil
	case typ == "bytes":
		raw, err := canonicalHex(value)
		if err != nil {
			return word, err
		}
		return Keccak256(raw), nil
	case typ == "address":
		raw, err := canonicalHex(value)
		if err != nil || len(raw) != 20 {
			return word, errors.New("address is not 20 bytes of lowercase hex")
		}
		copy(word[12:], raw)
		return word, nil
	case typ == "bool":
		flag, ok := value.(bool)
		if !ok {
			return word, errors.New("bool value is not a bool")
		}
		if flag {
			word[31] = 1
		}
		return word, nil
	case strings.HasPrefix(typ, "bytes"):
		size, err := strconv.Atoi(strings.TrimPrefix(typ, "bytes"))
		if err != nil || size < 1 || size > 32 {
			return word, fmt.Errorf("unknown type %s", typ)
		}
		raw, err := canonicalHex(value)
		if err != nil || len(raw) != size {
			return word, fmt.Errorf("%s value is not %d bytes of lowercase hex", typ, size)
		}
		copy(word[:], raw)
		return word, nil
	case strings.HasPrefix(typ, "uint"):
		size, err := strconv.Atoi(strings.TrimPrefix(typ, "uint"))
		if err != nil || size < 8 || size > 256 || size%8 != 0 {
			return word, fmt.Errorf("unknown type %s", typ)
		}
		number, err := decimal(value)
		if err != nil {
			return word, err
		}
		if number.Sign() < 0 || number.BitLen() > size {
			return word, fmt.Errorf("%s value %s is out of range", typ, number)
		}
		number.FillBytes(word[:])
		return word, nil
	}
	return word, fmt.Errorf("unsupported type %s", typ)
}

func decimal(value any) (*big.Int, error) {
	var text string
	switch typed := value.(type) {
	case string:
		text = typed
	case json.Number:
		text = typed.String()
	default:
		return nil, errors.New("integer value is not a decimal string")
	}
	number, ok := new(big.Int).SetString(text, 10)
	if !ok || number.String() != text {
		return nil, fmt.Errorf("integer %q is not canonical decimal", text)
	}
	return number, nil
}

func canonicalHex(value any) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, errors.New("hex value is not a string")
	}
	raw, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(raw) != text {
		return nil, fmt.Errorf("%q is not lowercase hex without a prefix", text)
	}
	return raw, nil
}

// Domain is an EIP712Domain in the two shapes the protocol uses: the TrueOpen
// domains carry name, version and chainId; the transaction domain inherited
// from cosmos/evm adds verifyingContract and salt, both typed string.
type Domain struct {
	Name              string
	Version           string
	ChainID           string
	VerifyingContract *string
	Salt              *string
}

// Types returns the EIP712Domain struct for this domain's shape.
func (d Domain) Types() Types {
	fields := []Field{{"string", "name"}, {"string", "version"}, {"uint256", "chainId"}}
	if d.VerifyingContract != nil || d.Salt != nil {
		fields = append(fields, Field{"string", "verifyingContract"}, Field{"string", "salt"})
	}
	return Types{"EIP712Domain": fields}
}

// Separator is hashStruct(EIP712Domain).
func (d Domain) Separator() ([32]byte, error) {
	message := map[string]any{"name": d.Name, "version": d.Version, "chainId": d.ChainID}
	if d.VerifyingContract != nil || d.Salt != nil {
		if d.VerifyingContract == nil || d.Salt == nil {
			return [32]byte{}, errors.New("verifyingContract and salt come together")
		}
		message["verifyingContract"] = *d.VerifyingContract
		message["salt"] = *d.Salt
	}
	return d.Types().HashStruct("EIP712Domain", message)
}

// SigningDigest is keccak256(0x19 || 0x01 || domainSeparator || hashStruct).
func SigningDigest(domainSeparator, hashStruct [32]byte) [32]byte {
	return Keccak256([]byte{0x19, 0x01}, domainSeparator[:], hashStruct[:])
}
