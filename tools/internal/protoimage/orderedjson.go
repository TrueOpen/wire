package protoimage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Node is a JSON value that remembers the order its object keys were written
// in. encoding/json round-trips an object through a map and sorts the keys,
// which would reshuffle every generated OpenAPI document and bury the handful
// of schema changes this tool makes in a whole-file diff. A reviewer has to be
// able to see that only the annotated bytes properties moved.
type Node struct {
	// Kind is 'o' for object, 'a' for array, 'v' for anything else.
	Kind byte

	Keys   []string // object keys, in document order
	Values []*Node  // object values, parallel to Keys
	Elems  []*Node  // array elements

	Scalar json.RawMessage // strings, numbers, booleans, null
}

// ParseJSON decodes into a Node, preserving object key order. Numbers are kept
// verbatim, so a float that would lose precision through float64 survives.
func ParseJSON(raw []byte) (*Node, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	node, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after top-level JSON value")
	}
	return node, nil
}

func parseValue(decoder *json.Decoder) (*Node, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	return parseFrom(decoder, token)
}

func parseFrom(decoder *json.Decoder, token json.Token) (*Node, error) {
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			node := &Node{Kind: 'o'}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is %T, not a string", keyToken)
				}
				value, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				node.Keys = append(node.Keys, key)
				node.Values = append(node.Values, value)
			}
			if _, err := decoder.Token(); err != nil { // closing brace
				return nil, err
			}
			return node, nil
		case '[':
			node := &Node{Kind: 'a'}
			for decoder.More() {
				elem, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				node.Elems = append(node.Elems, elem)
			}
			if _, err := decoder.Token(); err != nil { // closing bracket
				return nil, err
			}
			return node, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %q", t)
	default:
		encoded, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		return &Node{Kind: 'v', Scalar: encoded}, nil
	}
}

// String returns the value of a string scalar.
func (n *Node) String() (string, bool) {
	if n == nil || n.Kind != 'v' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(n.Scalar, &value); err != nil {
		return "", false
	}
	return value, true
}

// Get returns the value stored under key, or nil.
func (n *Node) Get(key string) *Node {
	if n == nil || n.Kind != 'o' {
		return nil
	}
	for i, existing := range n.Keys {
		if existing == key {
			return n.Values[i]
		}
	}
	return nil
}

// Set replaces the value under key in place, or appends it if absent, so an
// edited object keeps the order it was parsed in.
func (n *Node) Set(key string, value *Node) {
	for i, existing := range n.Keys {
		if existing == key {
			n.Values[i] = value
			return
		}
	}
	n.Keys = append(n.Keys, key)
	n.Values = append(n.Values, value)
}

// Delete removes key if present.
func (n *Node) Delete(key string) {
	for i, existing := range n.Keys {
		if existing == key {
			n.Keys = append(n.Keys[:i], n.Keys[i+1:]...)
			n.Values = append(n.Values[:i], n.Values[i+1:]...)
			return
		}
	}
}

// StringNode builds a JSON string scalar.
func StringNode(value string) *Node {
	encoded, _ := json.Marshal(value)
	return &Node{Kind: 'v', Scalar: encoded}
}

// IntNode builds a JSON number scalar.
func IntNode(value int) *Node {
	return &Node{Kind: 'v', Scalar: json.RawMessage(fmt.Sprintf("%d", value))}
}

func (n *Node) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := n.write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *Node) write(buf *bytes.Buffer) error {
	switch n.Kind {
	case 'o':
		buf.WriteByte('{')
		for i, key := range n.Keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(encoded)
			buf.WriteByte(':')
			if err := n.Values[i].write(buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case 'a':
		buf.WriteByte('[')
		for i, elem := range n.Elems {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := elem.write(buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		if len(n.Scalar) == 0 {
			buf.WriteString("null")
			return nil
		}
		buf.Write(n.Scalar)
	}
	return nil
}

// MarshalIndentJSON renders the node with the two-space indentation the
// generated documents already use.
func MarshalIndentJSON(node *Node) ([]byte, error) {
	compact, err := node.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
