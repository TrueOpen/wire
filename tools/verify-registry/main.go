package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// domainPattern accepts any registered generation, not only V1. Canonical
	//requires a new _V2-or-higher domain whenever a preimage
	// changes shape, so a verifier that only ever accepts _V1 cannot express the
	// upgrade the same section mandates. The version is not waved through: see
	// validateGeneration.
	domainPattern = regexp.MustCompile(`^TRUEOPEN_(?P<base>[A-Z0-9_]+)_V(?P<version>[1-9][0-9]*)$`)
	baseIndex     = domainPattern.SubexpIndex("base")
	versionIndex  = domainPattern.SubexpIndex("version")
)

const nodeRegistryRepository = "https://github.com/TrueOpen/node"

var phase0RequiredDomains = []string{
	"TRUEOPEN_BURN_BOND_V1",
	"TRUEOPEN_GENERATED_TOKEN_IDS_V1",
	"TRUEOPEN_INFER_RECEIPT_V2",
	"TRUEOPEN_INPUT_TOKEN_IDS_V1",
	"TRUEOPEN_MINT_BOND_V1",
	"TRUEOPEN_OUTPUT_CHUNK_EQUIVOCATION_V1",
	"TRUEOPEN_WORKER_VALUE_COMMITMENT_V2",
}

var phase0RetiredDomains = []string{
	"TRUEOPEN_INFER_RECEIPT_V1",
	"TRUEOPEN_WORKER_VALUE_COMMITMENT_V1",
}

type registry struct {
	Schema           string   `json:"schema"`
	Status           string   `json:"status"`
	SourceRepository string   `json:"source_repository"`
	SourceCommit     string   `json:"source_commit"`
	Domains          []domain `json:"domains"`
}

type domain struct {
	Domain  string   `json:"domain"`
	Framing string   `json:"framing"`
	Fields  []string `json:"fields"`
	// Discriminator and Variants describe a domain whose preimage shape depends on
	// the value of its last fixed field. Fields is then the head every variant
	// shares, and head ++ variant.fields is the order for that variant.
	//
	// Two V1 domains need it: TRUEOPEN_QUERY_SELECTOR_V1, whose selector fields are
	// per-RPC, and TRUEOPEN_BUILDER_EVIDENCE_CONTENT_V1, whose branch is selected by a
	// oneof tag. Neither has one field order, and before this both rows said so in
	// prose - which a verifier cannot check and a client cannot use.
	Discriminator string    `json:"discriminator,omitempty"`
	Variants      []variant `json:"variants,omitempty"`
	// Origin names the review that authorized a row the pinned node source_commit
	// does not contain. A copy of that commit leaves it absent; anything newer has
	// to say where it came from, or "bootstrap-copy" stops meaning anything.
	Origin *domainOrigin `json:"origin,omitempty"`
	// Supersedes and SupersededBy link the two generations of one domain. They are
	// checked in both directions so a V2 cannot appear without the V1 it replaces
	// admitting it has been replaced - unless that V1 was never registered here at
	// all, which supersedes.registered states explicitly rather than by omission.
	Supersedes                   *supersession `json:"supersedes,omitempty"`
	SupersededBy                 string        `json:"superseded_by,omitempty"`
	Producer                     string        `json:"producer"`
	Consumers                    string        `json:"consumers"`
	Store                        string        `json:"store"`
	Event                        string        `json:"event"`
	Query                        string        `json:"query"`
	ContractSection              string        `json:"contract_section"`
	RegisteredInContract         bool          `json:"registered_in_contract"`
	PreimageDivergesFromContract bool          `json:"preimage_diverges_from_contract"`
	Note                         string        `json:"note,omitempty"`
}

type domainOrigin struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Review     string `json:"review"`
}

// supersession names the generation a domain replaces. Registered says whether
// that predecessor is a row in this registry: TRUEOPEN_BUILDER_EVIDENCE_CONTENT_V2
// replaces a live V1 row, while TRUEOPEN_BUS_ENVELOPE_V2 replaces a projection that
// was retired before it was ever registered. Both are legitimate; conflating
// them is not, because "the V1 row is missing" and "the V1 row was never written"
// need different evidence from a reviewer.
type supersession struct {
	Domain     string `json:"domain"`
	Registered bool   `json:"registered"`
	Reason     string `json:"reason,omitempty"`
}

type variant struct {
	// Key is the discriminator value that selects this variant, spelled exactly as
	// a golden vector's "variant" spells it: a fully-qualified /package.Service/Method
	// literal for the query selector, "oneof_tag=N" for a selected proto oneof branch.
	Key string `json:"key"`
	// Fields are the ordered field names that follow the head. An empty tail is a
	// real shape and must carry a note saying why.
	Fields []string `json:"fields,omitempty"`
	Note   string   `json:"note,omitempty"`
}

type framingRegistry struct {
	Schema           string            `json:"schema"`
	Status           string            `json:"status"`
	SourceRepository string            `json:"source_repository"`
	SourceCommit     string            `json:"source_commit"`
	Hash             string            `json:"hash"`
	IntegerEncoding  map[string]string `json:"integer_encoding"`
	Framings         []framing         `json:"framings"`
	Signature        signatureEncoding `json:"signature_encoding"`
}

type framing struct {
	Name        string `json:"name"`
	Preimage    string `json:"preimage,omitempty"`
	Digest      string `json:"digest,omitempty"`
	DomainFrame string `json:"domain_frame,omitempty"`
	Leaf        string `json:"leaf,omitempty"`
	Node        string `json:"node,omitempty"`
	Empty       string `json:"empty,omitempty"`
	OddNode     string `json:"odd_node,omitempty"`
	// Peaks and Fold belong to MMR_ROOT_V1 only. An append-only tree needs both
	// written down: the peak shape follows from the leaf count, and the fold
	// direction does not, so an implementation that folds the other way agrees
	// on every leaf count whose popcount is below three and then diverges.
	Peaks   string `json:"peaks,omitempty"`
	Fold    string `json:"fold,omitempty"`
	Sorting string `json:"sorting,omitempty"`
}

type signatureEncoding struct {
	Algorithm       string   `json:"algorithm"`
	PublicKey       string   `json:"public_key"`
	Signature       string   `json:"signature"`
	Hex             string   `json:"hex"`
	Requirements    []string `json:"requirements"`
	SignatureDigest string   `json:"signature_digest"`
}

func main() {
	path := flag.String("registry", "registry/v1/domains.json", "domain registry path")
	framingPath := flag.String("framing", "registry/v1/framing.json", "framing registry path")
	flag.Parse()
	if err := verify(*path, *framingPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(path, framingPath string) error {
	framingSourceCommit, err := verifyFraming(framingPath)
	if err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var value registry
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("decode domain registry: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode trailing domain registry data: %w", err)
		}
		return fmt.Errorf("domain registry contains multiple JSON values")
	}
	if value.Schema != "trueopen-domain-registry-v1" {
		return fmt.Errorf("unsupported domain registry schema %q", value.Schema)
	}
	if value.Status != "bootstrap-copy" && value.Status != "authoritative" {
		return fmt.Errorf("invalid domain registry status %q", value.Status)
	}
	if !strings.HasPrefix(value.SourceRepository, "https://") || !commitPattern.MatchString(value.SourceCommit) {
		return fmt.Errorf("domain registry source repository or commit is invalid")
	}
	if value.SourceCommit != framingSourceCommit {
		return fmt.Errorf("domain and framing registries use different source commits")
	}
	if len(value.Domains) == 0 {
		return fmt.Errorf("domain registry must not be empty")
	}

	allowedFraming := map[string]struct{}{
		"H_V1": {}, "H_FIELDS_V1": {}, "MERKLE_ROOT_V1": {}, "MMR_ROOT_V1": {},
	}
	byDomain := make(map[string]domain, len(value.Domains))
	ordered := make([]string, 0, len(value.Domains))
	for i, item := range value.Domains {
		if !domainPattern.MatchString(item.Domain) {
			return fmt.Errorf("domain %d has invalid name %q", i, item.Domain)
		}
		if _, exists := byDomain[item.Domain]; exists {
			return fmt.Errorf("duplicate domain %q", item.Domain)
		}
		byDomain[item.Domain] = item
		ordered = append(ordered, item.Domain)
		if _, exists := allowedFraming[item.Framing]; !exists {
			return fmt.Errorf("domain %q has invalid framing %q", item.Domain, item.Framing)
		}
		if err := validateDomain(item); err != nil {
			return err
		}
		if err := validateGeneration(item, value.SourceCommit); err != nil {
			return err
		}
	}
	if err := validateSupersessionLinks(byDomain); err != nil {
		return err
	}
	if value.SourceRepository == nodeRegistryRepository {
		if err := validatePhase0DomainInventory(byDomain); err != nil {
			return err
		}
	}
	wantOrder := append([]string(nil), ordered...)
	sort.Strings(wantOrder)
	if strings.Join(ordered, "\x00") != strings.Join(wantOrder, "\x00") {
		return fmt.Errorf("domain registry must be sorted by domain")
	}

	fmt.Printf("verified %d wire domains\n", len(value.Domains))
	return nil
}

func validatePhase0DomainInventory(byDomain map[string]domain) error {
	for _, name := range phase0RequiredDomains {
		if _, exists := byDomain[name]; !exists {
			return fmt.Errorf("phase 0 registry is missing required domain %q", name)
		}
	}
	for _, name := range phase0RetiredDomains {
		if _, exists := byDomain[name]; exists {
			return fmt.Errorf("phase 0 registry retains retired domain %q", name)
		}
	}
	return nil
}

// splitGeneration returns the base name and generation of a registered domain.
// The caller has already matched domainPattern.
func splitGeneration(name string) (string, int, error) {
	match := domainPattern.FindStringSubmatch(name)
	// The pattern admits digits without an upper bound, so a name like
	// TRUEOPEN_X_V99999999999999999999999 matches and then overflows. That is a bad
	// row, not a bug in this tool, so it fails as a readable error rather than a
	// stack trace.
	version, err := strconv.Atoi(match[versionIndex])
	if err != nil {
		return "", 0, fmt.Errorf("domain %q has an unusable generation number: %w", name, err)
	}
	return match[baseIndex], version, nil
}

// validateGeneration is what keeps "accepts V2" from degrading into "accepts
// anything". A V1 row may be a plain copy of the node registry at source_commit.
// A higher generation cannot be: source_commit predates the decision that
// created it, so the row has to name the review that authorized it, and it has
// to name the generation it replaces - Canonicalupgrades a
// domain, it does not invent an unrelated one.
func validateGeneration(item domain, sourceCommit string) error {
	base, version, err := splitGeneration(item.Domain)
	if err != nil {
		return err
	}
	if version == 1 {
		if item.Supersedes != nil {
			return fmt.Errorf("domain %q is the first generation and cannot supersede %q",
				item.Domain, item.Supersedes.Domain)
		}
		return nil
	}
	if item.Origin == nil {
		return fmt.Errorf("domain %q postdates the pinned source commit %s and must name the review that registered it",
			item.Domain, sourceCommit)
	}
	if !strings.HasPrefix(item.Origin.Repository, "https://") || !commitPattern.MatchString(item.Origin.Commit) ||
		strings.TrimSpace(item.Origin.Review) == "" {
		return fmt.Errorf("domain %q has an incomplete origin", item.Domain)
	}
	if item.Origin.Commit == sourceCommit {
		return fmt.Errorf("domain %q claims the pinned node source commit as its origin; a copied row needs no origin at all",
			item.Domain)
	}
	if item.Supersedes == nil {
		return fmt.Errorf("domain %q is generation %d and must name the generation it replaces", item.Domain, version)
	}
	want := fmt.Sprintf("TRUEOPEN_%s_V%d", base, version-1)
	if item.Supersedes.Domain != want {
		return fmt.Errorf("domain %q must supersede %q, got %q", item.Domain, want, item.Supersedes.Domain)
	}
	// An unregistered predecessor is the one case a reviewer cannot check against
	// another row, so it is the one case that has to argue for itself.
	if !item.Supersedes.Registered && strings.TrimSpace(item.Supersedes.Reason) == "" {
		return fmt.Errorf("domain %q supersedes unregistered %q and must record why that generation has no row",
			item.Domain, want)
	}
	if item.Supersedes.Registered && strings.TrimSpace(item.Supersedes.Reason) != "" {
		return fmt.Errorf("domain %q supersedes registered %q, whose own row carries the supersession note",
			item.Domain, want)
	}
	return nil
}

// validateSupersessionLinks closes the loop in the other direction. Without
// this, a V2 could quietly shadow a V1 that still advertises itself as current,
// which is exactly the "one domain, two interpretations" state §7 forbids.
func validateSupersessionLinks(byDomain map[string]domain) error {
	names := make([]string, 0, len(byDomain))
	for name := range byDomain {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		item := byDomain[name]
		if item.Supersedes != nil {
			older, exists := byDomain[item.Supersedes.Domain]
			if exists != item.Supersedes.Registered {
				if exists {
					return fmt.Errorf("domain %q declares %q unregistered, but it has a row here",
						name, item.Supersedes.Domain)
				}
				return fmt.Errorf("domain %q declares %q registered, but it has no row here",
					name, item.Supersedes.Domain)
			}
			if exists && older.SupersededBy != name {
				return fmt.Errorf("domain %q supersedes %q, but %q names %q as its successor",
					name, item.Supersedes.Domain, item.Supersedes.Domain, older.SupersededBy)
			}
		}
		if item.SupersededBy != "" {
			newer, exists := byDomain[item.SupersededBy]
			if !exists {
				return fmt.Errorf("domain %q is superseded by %q, which is not registered", name, item.SupersededBy)
			}
			if newer.Supersedes == nil || newer.Supersedes.Domain != name {
				return fmt.Errorf("domain %q is superseded by %q, which does not supersede it back",
					name, item.SupersededBy)
			}
			if strings.TrimSpace(item.Note) == "" {
				return fmt.Errorf("domain %q is superseded and must record what replaced it and from when", name)
			}
		}
	}
	return nil
}

func verifyFraming(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var value framingRegistry
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("decode framing registry: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return "", fmt.Errorf("decode trailing framing registry data: %w", err)
		}
		return "", fmt.Errorf("framing registry contains multiple JSON values")
	}
	if value.Schema != "trueopen-framing-registry-v1" || value.Hash != "SHA-256" {
		return "", fmt.Errorf("framing registry schema or hash is invalid")
	}
	if value.Status != "bootstrap-copy" && value.Status != "authoritative" {
		return "", fmt.Errorf("invalid framing registry status %q", value.Status)
	}
	if !strings.HasPrefix(value.SourceRepository, "https://") || !commitPattern.MatchString(value.SourceCommit) {
		return "", fmt.Errorf("framing registry source repository or commit is invalid")
	}
	if len(value.IntegerEncoding) == 0 {
		return "", fmt.Errorf("framing registry integer encoding is empty")
	}
	for name, encoding := range value.IntegerEncoding {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(encoding) == "" {
			return "", fmt.Errorf("framing registry contains an empty integer encoding")
		}
	}
	want := map[string]struct{}{"H_V1": {}, "H_FIELDS_V1": {}, "MERKLE_ROOT_V1": {}, "MMR_ROOT_V1": {}}
	seen := make(map[string]struct{}, len(value.Framings))
	for _, item := range value.Framings {
		if _, exists := want[item.Name]; !exists {
			return "", fmt.Errorf("unknown framing %q", item.Name)
		}
		if _, exists := seen[item.Name]; exists {
			return "", fmt.Errorf("duplicate framing %q", item.Name)
		}
		seen[item.Name] = struct{}{}
	}
	if len(seen) != len(want) {
		return "", fmt.Errorf("framing registry is incomplete")
	}
	if strings.TrimSpace(value.Signature.Algorithm) == "" || strings.TrimSpace(value.Signature.SignatureDigest) == "" ||
		len(value.Signature.Requirements) == 0 {
		return "", fmt.Errorf("signature encoding is incomplete")
	}
	return value.SourceCommit, nil
}

func validateDomain(item domain) error {
	if len(item.Fields) == 0 {
		return fmt.Errorf("domain %q has no fields", item.Domain)
	}
	seenFields := make(map[string]struct{}, len(item.Fields))
	for _, field := range item.Fields {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("domain %q contains an empty field", item.Domain)
		}
		if _, exists := seenFields[field]; exists {
			return fmt.Errorf("domain %q contains duplicate field %q", item.Domain, field)
		}
		seenFields[field] = struct{}{}
	}
	for name, value := range map[string]string{
		"producer": item.Producer, "consumers": item.Consumers, "store": item.Store,
		"event": item.Event, "query": item.Query, "contract_section": item.ContractSection,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("domain %q has empty %s", item.Domain, name)
		}
	}
	if (!item.RegisteredInContract || item.PreimageDivergesFromContract) && strings.TrimSpace(item.Note) == "" {
		return fmt.Errorf("domain %q requires a contract-gap note", item.Domain)
	}
	return validateVariants(item, seenFields)
}

// validateVariants checks the structural rules a discriminated domain has to
// satisfy before a client can resolve a preimage against it. They are the same
// rules the node registry asserts on its own side; this is the wire copy's
// independent check, not a restatement of the node test.
func validateVariants(item domain, headFields map[string]struct{}) error {
	if len(item.Variants) == 0 {
		if strings.TrimSpace(item.Discriminator) != "" {
			return fmt.Errorf("domain %q names discriminator %q but has no variants to select",
				item.Domain, item.Discriminator)
		}
		return nil
	}
	if item.Framing != "H_FIELDS_V1" {
		return fmt.Errorf("domain %q has variants but framing %q; only an ordered-field domain can have a discriminated tail",
			item.Domain, item.Framing)
	}
	// The discriminator is the LAST head field, so the selected variant's fields
	// follow it directly and head ++ variant.fields is the whole order. A
	// discriminator anywhere else would leave the tail's position undefined.
	if item.Discriminator != item.Fields[len(item.Fields)-1] {
		return fmt.Errorf("domain %q discriminator %q is not the last of its fields %v",
			item.Domain, item.Discriminator, item.Fields)
	}
	seenKeys := make(map[string]struct{}, len(item.Variants))
	previousKey := ""
	for _, entry := range item.Variants {
		if strings.TrimSpace(entry.Key) == "" {
			return fmt.Errorf("domain %q has a variant with no discriminator value", item.Domain)
		}
		if _, exists := seenKeys[entry.Key]; exists {
			return fmt.Errorf("domain %q registers variant %q twice", item.Domain, entry.Key)
		}
		seenKeys[entry.Key] = struct{}{}
		if previousKey != "" && entry.Key <= previousKey {
			return fmt.Errorf("domain %q variants must be sorted by key: %q follows %q",
				item.Domain, entry.Key, previousKey)
		}
		previousKey = entry.Key

		if len(entry.Fields) == 0 && strings.TrimSpace(entry.Note) == "" {
			return fmt.Errorf("domain %q variant %q has no fields and no note saying why", item.Domain, entry.Key)
		}
		if len(entry.Fields) != 0 && strings.TrimSpace(entry.Note) != "" {
			return fmt.Errorf("domain %q variant %q has fields, so its note has nothing left to explain",
				item.Domain, entry.Key)
		}
		seenTail := make(map[string]struct{}, len(entry.Fields))
		for _, field := range entry.Fields {
			if strings.TrimSpace(field) == "" {
				return fmt.Errorf("domain %q variant %q contains an empty field", item.Domain, entry.Key)
			}
			if strings.HasPrefix(field, "repeated") {
				return fmt.Errorf("domain %q variant %q ends in a repeated group; a discriminated tail and a variable-length tail cannot both be last",
					item.Domain, entry.Key)
			}
			if _, exists := headFields[field]; exists {
				return fmt.Errorf("domain %q variant %q repeats head field %q", item.Domain, entry.Key, field)
			}
			if _, exists := seenTail[field]; exists {
				return fmt.Errorf("domain %q variant %q contains duplicate field %q", item.Domain, entry.Key, field)
			}
			seenTail[field] = struct{}{}
		}
	}
	return nil
}
