package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/TrueOpen/wire/tools/internal/eip712"
)

// EIP-712 vectors publish a whole chain of derived values: a key's public key
// and address, a domain's separator, a struct's type hash and hash_struct, the
// signing digest, the signature and the address it recovers to. Every one of
// them is recomputed here. A signature is checked twice: it must recover to the
// published address, and when the vector names its signer it must also be the
// exact RFC 6979 signature of that key, so a signature produced over some other
// digest cannot pass by recovering to a plausible address.

// eip712Checker holds the per-document context: the named test keys and the
// sections negative rows refer to.
type eip712Checker struct {
	*fileChecker
	keys     map[string]eip712.Key
	sections map[string]map[string]any
}

func (c *fileChecker) checkEIP712Document(document any) {
	root, ok := document.(map[string]any)
	if !ok {
		return
	}
	checker := &eip712Checker{fileChecker: c, keys: map[string]eip712.Key{}, sections: map[string]map[string]any{}}
	names := sortedKeys(root)
	for _, name := range names {
		if object, ok := root[name].(map[string]any); ok {
			if _, hasKey := object["private_key"]; hasKey {
				checker.checkKey(name, object)
			}
		}
	}
	for _, name := range names {
		object, ok := root[name].(map[string]any)
		if !ok {
			continue
		}
		switch {
		case isDomainBlock(object):
			checker.checkDomainBlock(c.name+"."+name, object)
		case isTypedSection(object):
			checker.sections[name] = object
			checker.checkSection(c.name+"."+name, object)
		case object["type_graph"] != nil && object["canonical_amino_json"] != nil:
			checker.checkAminoTransaction(c.name+"."+name, object, root)
		}
	}
	// A document whose vectors share one domain and primary type states them
	// once at the top and lists messages below.
	if domain, ok := root["domain"].(map[string]any); ok && root["encode_type"] != nil {
		for index, raw := range listOf(root["vectors"]) {
			if row, ok := raw.(map[string]any); ok && row["message"] != nil {
				inherited := map[string]any{"domain": domain, "encode_type": root["encode_type"], "type_hash": root["type_hash"]}
				for key, value := range row {
					inherited[key] = value
				}
				checker.checkSection(fmt.Sprintf("%s.vectors[%d]", c.name, index), inherited)
			}
		}
	}
	for _, raw := range listOf(root["request_auth_negative_cases"]) {
		if row, ok := raw.(map[string]any); ok {
			checker.checkNegative(row)
		}
	}
}

func isDomainBlock(object map[string]any) bool {
	_, hasSeparator := object["domain_separator"]
	_, hasName := object["name"]
	_, hasChain := object["chain_id"]
	return hasSeparator && hasName && hasChain
}

func isTypedSection(object map[string]any) bool {
	_, hasDomain := object["domain"].(map[string]any)
	_, hasType := object["encode_type"].(string)
	_, hasMessage := object["message"].(map[string]any)
	return hasDomain && hasType && hasMessage
}

func (c *eip712Checker) checkKey(name string, object map[string]any) {
	where := c.name + "." + name
	key, err := eip712.ParseKey(stringOf(object["private_key"]))
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	c.keys[name] = key
	c.report.keys++
	address := key.Address()
	keccak := eip712.Keccak256(key.PublicXY())
	for field, want := range map[string]string{
		"pub_compressed":                hex.EncodeToString(key.PublicCompressed()),
		"pub_uncompressed_xy":           hex.EncodeToString(key.PublicXY()),
		"keccak256_pub_uncompressed_xy": hex.EncodeToString(keccak[:]),
		"address_bytes":                 hex.EncodeToString(address[:]),
		"address_0x":                    eip712.ChecksumAddress(address),
	} {
		if published, ok := object[field]; ok && published != want {
			c.fail("%s: %s is %v, the private key derives %s", where, field, published, want)
		}
	}
}

func domainOf(object map[string]any) eip712.Domain {
	domain := eip712.Domain{Name: stringOf(object["name"]), Version: stringOf(object["version"]), ChainID: stringOf(object["chain_id"])}
	if value, ok := object["verifying_contract"].(string); ok {
		domain.VerifyingContract = &value
	}
	if value, ok := object["salt"].(string); ok {
		domain.Salt = &value
	}
	return domain
}

// checkDomainBlock recomputes a domain's encodeType, type hash and separator.
func (c *eip712Checker) checkDomainBlock(where string, object map[string]any) ([32]byte, bool) {
	domain := domainOf(object)
	separator, err := domain.Separator()
	if err != nil {
		c.fail("%s: %v", where, err)
		return separator, false
	}
	types := domain.Types()
	typeHash := types.TypeHash("EIP712Domain")
	c.expectEqual(where, "encode_type", object["encode_type"], types.EncodeType("EIP712Domain"))
	c.expectEqual(where, "type_hash", object["type_hash"], hex.EncodeToString(typeHash[:]))
	c.expectEqual(where, "domain_separator", object["domain_separator"], hex.EncodeToString(separator[:]))
	c.report.domains++
	return separator, true
}

// expectEqual compares a published value, when present, with the recomputed one.
func (c *eip712Checker) expectEqual(where, field string, published any, want string) {
	if published == nil {
		return
	}
	if published != want {
		c.fail("%s: %s is %v, recomputed %s", where, field, published, want)
	}
}

// digestOf computes the signing digest of a typed section with optional
// overrides applied to its domain and message, and returns the parts a caller
// compares.
func (c *eip712Checker) digestOf(where string, section map[string]any, domainEdit, messageEdit map[string]any) (typeHash, hashStruct, digest [32]byte, ok bool) {
	domainObject := cloneJSON(section["domain"]).(map[string]any)
	for key, value := range domainEdit {
		domainObject[key] = value
	}
	separator, err := domainOf(domainObject).Separator()
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	primary, types, err := eip712.ParseEncodeType(stringOf(section["encode_type"]))
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	message := cloneJSON(section["message"]).(map[string]any)
	for key, value := range messageEdit {
		if _, exists := message[key]; !exists {
			c.fail("%s: edit names %q, which is not a member of the message", where, key)
			return
		}
		message[key] = value
	}
	hashStruct, err = types.HashStruct(primary, message)
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	return types.TypeHash(primary), hashStruct, eip712.SigningDigest(separator, hashStruct), true
}

func (c *eip712Checker) checkSection(where string, section map[string]any) {
	domain := section["domain"].(map[string]any)
	if _, published := domain["domain_separator"]; published {
		if _, ok := c.checkDomainBlock(where+".domain", domain); !ok {
			return
		}
	}
	typeHash, hashStruct, digest, ok := c.digestOf(where, section, nil, nil)
	if !ok {
		return
	}
	c.report.eip712++
	c.expectEqual(where, "type_hash", section["type_hash"], hex.EncodeToString(typeHash[:]))
	c.expectEqual(where, "hash_struct", section["hash_struct"], hex.EncodeToString(hashStruct[:]))
	c.expectEqual(where, "signing_digest", section["signing_digest"], hex.EncodeToString(digest[:]))
	c.checkSignature(where, section, digest)
}

// checkSignature recovers a published signature and, when the signer is known,
// requires it to be that key's exact signature. A vector with a signature but
// no signer field was produced by the document's account key.
func (c *eip712Checker) checkSignature(where string, object map[string]any, digest [32]byte) {
	signatureHex, ok := object["signature_65"].(string)
	if !ok {
		return
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		c.fail("%s: signature_65 is not hex", where)
		return
	}
	c.report.signatures++
	recovered, err := eip712.Recover(digest, signature)
	if err != nil {
		c.fail("%s: signature_65 does not recover: %v", where, err)
		return
	}
	c.expectEqual(where, "recovered_address", object["recovered_address"], hex.EncodeToString(recovered[:]))
	signer := "account"
	if named, ok := object["signer"].(string); ok {
		signer = named
	}
	key, known := c.keys[signer]
	if !known {
		c.fail("%s: signer %q has no key in this document", where, signer)
		return
	}
	if got := hex.EncodeToString(key.Sign(digest)); got != signatureHex {
		c.fail("%s: signature_65 is not the RFC 6979 signature of %s over the signing digest (%s)", where, signer, abbreviate(got))
	}
}

// checkAminoTransaction rebuilds the Tx typed message from the canonical amino
// JSON, the only input the transaction path signs, with msgs replaced by msg0.
func (c *eip712Checker) checkAminoTransaction(where string, object map[string]any, root map[string]any) {
	domainObject, ok := root["transaction_domain"].(map[string]any)
	if !ok {
		c.fail("%s: no transaction_domain to sign under", where)
		return
	}
	var definitions []string
	for _, raw := range listOf(object["type_graph"]) {
		definitions = append(definitions, stringOf(raw))
	}
	primary, types, err := eip712.ParseTypeGraph(definitions)
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	c.expectEqual(where, "encode_type", object["encode_type"], types.EncodeType(primary))
	var message map[string]any
	if err := json.Unmarshal([]byte(stringOf(object["canonical_amino_json"])), &message); err != nil {
		c.fail("%s: canonical_amino_json: %v", where, err)
		return
	}
	msgs, _ := message["msgs"].([]any)
	if len(msgs) != 1 {
		c.fail("%s: the transaction path signs exactly one message", where)
		return
	}
	delete(message, "msgs")
	message["msg0"] = msgs[0]
	hashStruct, err := types.HashStruct(primary, message)
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	separator, err := domainOf(domainObject).Separator()
	if err != nil {
		c.fail("%s: %v", where, err)
		return
	}
	if stringOf(domainObject["chain_id"]) != stringOf(object["evm_chain_id"]) {
		c.fail("%s: evm_chain_id differs from the transaction domain chain_id", where)
	}
	typeHash := types.TypeHash(primary)
	digest := eip712.SigningDigest(separator, hashStruct)
	c.report.eip712++
	c.expectEqual(where, "type_hash", object["type_hash"], hex.EncodeToString(typeHash[:]))
	c.expectEqual(where, "hash_struct", object["hash_struct"], hex.EncodeToString(hashStruct[:]))
	c.expectEqual(where, "signing_digest", object["signing_digest"], hex.EncodeToString(digest[:]))
	c.checkSignature(where, object, digest)
}

// checkNegative recomputes one negative request-authentication row. A row
// states what the signer signed ("signed": signer plus edits to the base
// section) and what the verifier rebuilds ("verified": edits to the base
// section). A row without "signed" reuses the base signature; a row without
// "verified" checks against the base section as the signer changed it. The
// published signing_digest is the verifier's digest and recovered_address is
// what the signature recovers to over it. A verification_context row is a
// session-grant window decision, recomputed from the base grant's expiry.
func (c *eip712Checker) checkNegative(row map[string]any) {
	where := fmt.Sprintf("%s.request_auth_negative_cases[%s]", c.name, rowName(row))
	baseName := stringOf(row["base"])
	base, ok := c.sections[baseName]
	if !ok {
		c.fail("%s: base %q is not a typed section of this document", where, baseName)
		return
	}
	expect := stringOf(row["expect"])
	if expect != "reject" && expect != "accept" {
		c.fail("%s: expect must be reject or accept", where)
	}
	c.report.negatives++

	signature := stringOf(base["signature_65"])
	signed, hasSigned := row["signed"].(map[string]any)
	if hasSigned {
		signer := stringOf(signed["signer"])
		key, known := c.keys[signer]
		if !known {
			c.fail("%s: signed.signer %q has no key in this document", where, signer)
			return
		}
		_, _, signedDigest, ok := c.digestOf(where, base, mapOf(signed["domain"]), mapOf(signed["message"]))
		if !ok {
			return
		}
		signature = hex.EncodeToString(key.Sign(signedDigest))
		c.expectEqual(where, "signature_65", row["signature_65"], signature)
		if row["signature_65"] == nil {
			c.fail("%s: a signed row must publish its signature_65", where)
		}
	}
	verified, hasVerified := row["verified"].(map[string]any)
	if hasSigned || hasVerified {
		if !hasVerified {
			verified = map[string]any{}
		}
		_, _, digest, ok := c.digestOf(where, base, mapOf(verified["domain"]), mapOf(verified["message"]))
		if !ok {
			return
		}
		c.expectEqual(where, "signing_digest", row["signing_digest"], hex.EncodeToString(digest[:]))
		raw, _ := hex.DecodeString(signature)
		recovered, err := eip712.Recover(digest, raw)
		if err != nil {
			c.fail("%s: signature does not recover: %v", where, err)
			return
		}
		c.expectEqual(where, "recovered_address", row["recovered_address"], hex.EncodeToString(recovered[:]))
		if row["signing_digest"] == nil || row["recovered_address"] == nil {
			c.fail("%s: a signed or verified row must publish signing_digest and recovered_address", where)
		}
	}
	if context, ok := row["verification_context"].(map[string]any); ok {
		current, errCurrent := strconv.ParseUint(stringOf(context["current_height"]), 10, 64)
		window, errWindow := strconv.ParseUint(stringOf(context["max_session_grant_blocks"]), 10, 64)
		expiry, errExpiry := strconv.ParseUint(stringOf(mapOf(base["message"])["expiryHeight"]), 10, 64)
		if errCurrent != nil || errWindow != nil || errExpiry != nil {
			c.fail("%s: verification_context needs current_height, max_session_grant_blocks and a base grant expiryHeight", where)
			return
		}
		upper := current + window
		inWindow := upper >= current && current <= expiry && expiry <= upper
		if inWindow != (expect == "accept") {
			c.fail("%s: the grant window at height %d gives accept=%v, the row expects %s", where, current, inWindow, expect)
		}
	}
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func listOf(value any) []any {
	list, _ := value.([]any)
	return list
}

func mapOf(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

func stringOf(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	}
	return ""
}
