package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyRegistryAndDuplicateField(t *testing.T) {
	root := t.TempDir()
	framingPath := filepath.Join(root, "framing.json")
	registryPath := filepath.Join(root, "domains.json")
	writeRegistryJSON(t, framingPath, testFramingRegistry())
	value := testDomainRegistry()
	writeRegistryJSON(t, registryPath, value)
	if err := verify(registryPath, framingPath); err != nil {
		t.Fatalf("valid registry rejected: %v", err)
	}

	value.Domains[0].Fields = []string{"field", "field"}
	writeRegistryJSON(t, registryPath, value)
	if err := verify(registryPath, framingPath); err == nil {
		t.Fatal("duplicate domain field accepted")
	}
}

func TestVerifyRegistryRejectsUnsortedDomains(t *testing.T) {
	root := t.TempDir()
	framingPath := filepath.Join(root, "framing.json")
	registryPath := filepath.Join(root, "domains.json")
	writeRegistryJSON(t, framingPath, testFramingRegistry())
	value := testDomainRegistry()
	second := value.Domains[0]
	second.Domain = "TRUEOPEN_A_V1"
	value.Domains = append(value.Domains, second)
	writeRegistryJSON(t, registryPath, value)
	if err := verify(registryPath, framingPath); err == nil {
		t.Fatal("unsorted domains accepted")
	}
}

func TestValidatePhase0DomainInventory(t *testing.T) {
	valid := make(map[string]domain, len(phase0RequiredDomains))
	for _, name := range phase0RequiredDomains {
		valid[name] = domain{Domain: name}
	}
	if err := validatePhase0DomainInventory(valid); err != nil {
		t.Fatalf("valid Phase 0 inventory rejected: %v", err)
	}

	missing := make(map[string]domain, len(valid)-1)
	for name, item := range valid {
		if name != "TRUEOPEN_INFER_RECEIPT_V2" {
			missing[name] = item
		}
	}
	if err := validatePhase0DomainInventory(missing); err == nil {
		t.Fatal("inventory without InferReceiptV2 accepted")
	}

	valid["TRUEOPEN_INFER_RECEIPT_V1"] = domain{Domain: "TRUEOPEN_INFER_RECEIPT_V1"}
	if err := validatePhase0DomainInventory(valid); err == nil {
		t.Fatal("inventory retaining InferReceiptV1 accepted")
	}
}

// TestVerifyRegistryVariantRules covers the discriminated-tail schema. Each case
// is a shape that reads perfectly well and would let a client resolve a preimage
// the producer does not build, which is why the verifier has to refuse it rather
// than pass it through as prose used to be.
func TestVerifyRegistryVariantRules(t *testing.T) {
	valid := func() registry {
		value := testDomainRegistry()
		value.Domains[0].Fields = []string{"schema_version", "oneof_tag"}
		value.Domains[0].Discriminator = "oneof_tag"
		value.Domains[0].Variants = []variant{
			{Key: "oneof_tag=2", Fields: []string{"envelope"}},
			{Key: "oneof_tag=3", Note: "this branch carries no fields of its own"},
		}
		return value
	}

	for _, testCase := range []struct {
		name   string
		mutate func(*registry)
	}{
		{"accepts a well-formed variant list", nil},
		{"rejects variants without a discriminator", func(value *registry) {
			value.Domains[0].Discriminator = ""
		}},
		{"rejects a discriminator that is not the last head field", func(value *registry) {
			value.Domains[0].Discriminator = "schema_version"
		}},
		{"rejects a discriminator with no variants", func(value *registry) {
			value.Domains[0].Variants = nil
		}},
		{"rejects variants on a non-H_FIELDS_V1 domain", func(value *registry) {
			value.Domains[0].Framing = "H_V1"
			value.Domains[0].Fields = []string{"payload: codec"}
			value.Domains[0].Discriminator = "payload: codec"
		}},
		{"rejects duplicate variant keys", func(value *registry) {
			value.Domains[0].Variants[1].Key = value.Domains[0].Variants[0].Key
		}},
		{"rejects unsorted variant keys", func(value *registry) {
			value.Domains[0].Variants[0], value.Domains[0].Variants[1] =
				value.Domains[0].Variants[1], value.Domains[0].Variants[0]
		}},
		{"rejects an empty tail with no note", func(value *registry) {
			value.Domains[0].Variants[1].Note = ""
		}},
		{"rejects a note next to fields", func(value *registry) {
			value.Domains[0].Variants[0].Note = "unnecessary"
		}},
		{"rejects a variant field that repeats the head", func(value *registry) {
			value.Domains[0].Variants[0].Fields = []string{"oneof_tag"}
		}},
		{"rejects duplicate fields inside one variant", func(value *registry) {
			value.Domains[0].Variants[0].Fields = []string{"envelope", "envelope"}
		}},
		{"rejects a repeated group in a variant tail", func(value *registry) {
			value.Domains[0].Variants[0].Fields = []string{"repeated(envelope)"}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			framingPath := filepath.Join(root, "framing.json")
			registryPath := filepath.Join(root, "domains.json")
			writeRegistryJSON(t, framingPath, testFramingRegistry())
			value := valid()
			if testCase.mutate != nil {
				testCase.mutate(&value)
			}
			writeRegistryJSON(t, registryPath, value)
			err := verify(registryPath, framingPath)
			if testCase.mutate == nil {
				if err != nil {
					t.Fatalf("valid variant list rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid variant list accepted")
			}
		})
	}
}

// TestVerifyRegistryGenerationRules covers the reviewed-V2 mechanism. Canonical
// encoding_and_domain_hashing.md §7 requires a new _V2 domain whenever a preimage changes shape,
// so the verifier has to accept one - but a row that postdates the pinned node
// source_commit is no longer a copy of it, and every case below is a way of
// adding such a row without leaving a reviewer anything to check.
func TestVerifyRegistryGenerationRules(t *testing.T) {
	const monorepoCommit = "2222222222222222222222222222222222222222"
	reviewedOrigin := func() *domainOrigin {
		return &domainOrigin{
			Repository: "https://github.com/TrueOpen/monorepo",
			Commit:     monorepoCommit,
			Review:     "ADR-0013",
		}
	}
	// valid holds one superseded V1 and its reviewed V2 successor, sorted.
	valid := func() registry {
		value := testDomainRegistry()
		first := value.Domains[0]
		first.Domain = "TRUEOPEN_A_V1"
		first.SupersededBy = "TRUEOPEN_A_V2"
		first.Note = "superseded by TRUEOPEN_A_V2"
		second := value.Domains[0]
		second.Domain = "TRUEOPEN_A_V2"
		second.Origin = reviewedOrigin()
		second.Supersedes = &supersession{Domain: "TRUEOPEN_A_V1", Registered: true}
		value.Domains = []domain{first, second, value.Domains[0]}
		return value
	}

	for _, testCase := range []struct {
		name   string
		mutate func(*registry)
	}{
		{"accepts a reviewed V2 linked to its registered V1", nil},
		{"rejects a V2 with no origin", func(value *registry) {
			value.Domains[1].Origin = nil
		}},
		{"rejects a V2 whose origin is the pinned node commit", func(value *registry) {
			value.Domains[1].Origin.Commit = value.SourceCommit
		}},
		{"rejects a V2 with an incomplete origin", func(value *registry) {
			value.Domains[1].Origin.Review = "  "
		}},
		{"rejects a V2 that supersedes nothing", func(value *registry) {
			value.Domains[1].Supersedes = nil
		}},
		{"rejects a V2 that supersedes an unrelated domain", func(value *registry) {
			value.Domains[1].Supersedes.Domain = "TRUEOPEN_Z_V1"
		}},
		{"rejects a V2 that skips a generation", func(value *registry) {
			value.Domains[1].Domain = "TRUEOPEN_A_V3"
			value.Domains[0].SupersededBy = "TRUEOPEN_A_V3"
		}},
		{"rejects a V1 that claims to supersede something", func(value *registry) {
			value.Domains[2].Supersedes = &supersession{Domain: "TRUEOPEN_Y_V1", Registered: false, Reason: "why"}
		}},
		{"rejects a V2 claiming its registered V1 is unregistered", func(value *registry) {
			value.Domains[1].Supersedes.Registered = false
			value.Domains[1].Supersedes.Reason = "never existed"
		}},
		{"rejects a registered supersession that also argues its case", func(value *registry) {
			value.Domains[1].Supersedes.Reason = "also unregistered somehow"
		}},
		{"rejects a V1 that does not admit being superseded", func(value *registry) {
			value.Domains[0].SupersededBy = ""
			value.Domains[0].Note = ""
		}},
		{"rejects a V1 pointing at a successor that supersedes someone else", func(value *registry) {
			value.Domains[1].Supersedes.Domain = "TRUEOPEN_Z_V1"
			value.Domains[1].Domain = "TRUEOPEN_A_V2"
		}},
		{"rejects a superseded V1 with no note", func(value *registry) {
			value.Domains[0].Note = ""
		}},
		{"rejects a superseded_by target that is not registered", func(value *registry) {
			value.Domains[0].SupersededBy = "TRUEOPEN_A_V9"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			framingPath := filepath.Join(root, "framing.json")
			registryPath := filepath.Join(root, "domains.json")
			writeRegistryJSON(t, framingPath, testFramingRegistry())
			value := valid()
			if testCase.mutate != nil {
				testCase.mutate(&value)
			}
			writeRegistryJSON(t, registryPath, value)
			err := verify(registryPath, framingPath)
			if testCase.mutate == nil {
				if err != nil {
					t.Fatalf("valid generation chain rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid generation chain accepted")
			}
		})
	}
}

// TestVerifyRegistryAcceptsUnregisteredPredecessor is the TRUEOPEN_BUS_ENVELOPE_V2
// shape: the generation it replaces was retired before it was ever registered,
// so there is no V1 row to link and the row has to say so in words instead.
func TestVerifyRegistryAcceptsUnregisteredPredecessor(t *testing.T) {
	root := t.TempDir()
	framingPath := filepath.Join(root, "framing.json")
	registryPath := filepath.Join(root, "domains.json")
	writeRegistryJSON(t, framingPath, testFramingRegistry())

	value := testDomainRegistry()
	value.Domains[0].Domain = "TRUEOPEN_A_V2"
	value.Domains[0].Origin = &domainOrigin{
		Repository: "https://github.com/TrueOpen/monorepo",
		Commit:     "2222222222222222222222222222222222222222",
		Review:     "ADR-0013",
	}
	value.Domains[0].Supersedes = &supersession{
		Domain:     "TRUEOPEN_A_V1",
		Registered: false,
		Reason:     "retired before activation, never registered here",
	}
	writeRegistryJSON(t, registryPath, value)
	if err := verify(registryPath, framingPath); err != nil {
		t.Fatalf("unregistered predecessor rejected: %v", err)
	}

	value.Domains[0].Supersedes.Reason = ""
	writeRegistryJSON(t, registryPath, value)
	if err := verify(registryPath, framingPath); err == nil {
		t.Fatal("unregistered predecessor accepted without a reason")
	}
}

func testDomainRegistry() registry {
	return registry{
		Schema: "trueopen-domain-registry-v1", Status: "bootstrap-copy",
		SourceRepository: "https://example.com/source",
		SourceCommit:     "1111111111111111111111111111111111111111",
		Domains: []domain{{
			Domain: "TRUEOPEN_Z_V1", Framing: "H_FIELDS_V1", Fields: []string{"field"},
			Producer: "producer", Consumers: "consumers", Store: "store", Event: "event",
			Query: "query", ContractSection: "section", RegisteredInContract: true,
		}},
	}
}

func testFramingRegistry() framingRegistry {
	return framingRegistry{
		Schema: "trueopen-framing-registry-v1", Status: "bootstrap-copy",
		SourceRepository: "https://github.com/TrueOpen/node",
		SourceCommit:     "1111111111111111111111111111111111111111",
		Hash:             "SHA-256", IntegerEncoding: map[string]string{"uint32": "big-endian"},
		Framings: []framing{{Name: "H_V1"}, {Name: "H_FIELDS_V1"}, {Name: "MERKLE_ROOT_V1"}, {Name: "MMR_ROOT_V1"}},
		Signature: signatureEncoding{
			Algorithm: "secp256k1", SignatureDigest: "SHA256(raw)", Requirements: []string{"low-S"},
		},
	}
}

func writeRegistryJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRegistryFramingAllowlist(t *testing.T) {
	t.Run("accepts a domain on MMR_ROOT_V1", func(t *testing.T) {
		dir := t.TempDir()
		framingPath := filepath.Join(dir, "framing.json")
		writeRegistryJSON(t, framingPath, testFramingRegistry())

		value := testDomainRegistry()
		value.Domains[0].Framing = "MMR_ROOT_V1"
		value.Domains[0].Fields = []string{"leaves: ordered bytes, index = position"}
		path := filepath.Join(dir, "domains.json")
		writeRegistryJSON(t, path, value)

		if err := verify(path, framingPath); err != nil {
			t.Fatalf("MMR_ROOT_V1 domain rejected: %v", err)
		}
	})

	t.Run("rejects a framing the registry does not list", func(t *testing.T) {
		dir := t.TempDir()
		registry := testFramingRegistry()
		registry.Framings = append(registry.Framings, framing{Name: "MMR_ROOT_V2"})
		framingPath := filepath.Join(dir, "framing.json")
		writeRegistryJSON(t, framingPath, registry)

		path := filepath.Join(dir, "domains.json")
		writeRegistryJSON(t, path, testDomainRegistry())

		if err := verify(path, framingPath); err == nil {
			t.Fatal("an unlisted framing must be rejected")
		}
	})

	t.Run("rejects a domain naming an unlisted framing", func(t *testing.T) {
		dir := t.TempDir()
		framingPath := filepath.Join(dir, "framing.json")
		writeRegistryJSON(t, framingPath, testFramingRegistry())

		value := testDomainRegistry()
		value.Domains[0].Framing = "MMR_ROOT_V2"
		path := filepath.Join(dir, "domains.json")
		writeRegistryJSON(t, path, value)

		if err := verify(path, framingPath); err == nil {
			t.Fatal("a domain on an unlisted framing must be rejected")
		}
	})
}
