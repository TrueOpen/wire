package bus

import (
	"bytes"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cosmos/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The linked Builder evidence vectors, byte for byte. this contract requires the wire
// fixtures to contain them
// verbatim, so they are transcribed here rather than paraphrased. This test checks
// that this implementation and the document agree; a restated fixture would only
// check the implementation against itself.
//
// The two envelopes share every signed field except the payload's output_hash,
// which is what makes them an equivocation rather than a retry.
const (
	evidenceChainID       = "c"
	evidenceSenderAddress = "trueopen1wltmkp6cpvulh9ya7z0hhw0cpgwsvsdccd5man"
	evidenceWorkerAddress = "trueopen1j7r6u8nwvw93l2tc0wd75v07vu89lxyfqf8fut"

	envelopeAPayloadDigest    = "b1c7d68316733a4c88e88d531e390a76c1fc1ddcca22702ee6854dbf74fb9efd"
	envelopeABusSigningDigest = "c5d5aaf00bec3260adc43be9bbc62e47b3f041c381eb73cd67e2603385ef71db"
	envelopeABytes            = "08011201631a55747275656f70656e2e7665726966792e6f70656e2e3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313120052802322f747275656f70656e31776c746d6b7036637076756c68397961377a30686877306370677773767364636364356d616e380142016d4a2000000000000000000000000000000000000000000000000000000000000000005001580260056adf010a201111111111111111111111111111111111111111111111111111111111111111122022222222222222222222222222222222222222222222222222222222222222221a20555555555555555555555555555555555555555555555555555555555555555520012a203333333333333333333333333333333333333333333333333333333333333333322044444444444444444444444444444444444444444444444444444444444444443a2f747275656f70656e316a37723675386e77767739336c3274633077643735763037767538396c78796671663866757440017220b1c7d68316733a4c88e88d531e390a76c1fc1ddcca22702ee6854dbf74fb9efd7a4087b90f59327038e12342eb9d9f44bae52b0545ea7a054e384312205312a3358a29f75ecb7522c9f6b04d22072f1907734703f8b6883daf55b0d4653cb464911a"
	envelopeBBusSigningDigest = "b5430cb4b34d1f694fcab36aaf618251e7e1307a291ff2e774bf398662c8e674"
	envelopeBBytes            = "08011201631a55747275656f70656e2e7665726966792e6f70656e2e3131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313120052802322f747275656f70656e31776c746d6b7036637076756c68397961377a30686877306370677773767364636364356d616e380142016d4a2000000000000000000000000000000000000000000000000000000000000000005001580260056adf010a201111111111111111111111111111111111111111111111111111111111111111122022222222222222222222222222222222222222222222222222222222222222221a20555555555555555555555555555555555555555555555555555555555555555520012a203333333333333333333333333333333333333333333333333333333333333333322055555555555555555555555555555555555555555555555555555555555555553a2f747275656f70656e316a37723675386e77767739336c3274633077643735763037767538396c78796671663866757440017220d822e280965598a35c232e53c256de7e0890ad14a81be09b11c6974e641fe2d37a40231169ace9bdcfc40dcab77b85ba9190ebcd0ec69294defbc742ad32690b12f03fd9e5488e6bb2cb0f3d67636d440568c3c7c0b67dc639ec85fdbdc18ad3aec2"
	envelopeBPayloadDigest    = "d822e280965598a35c232e53c256de7e0890ad14a81be09b11c6974e641fe2d3"

	equivocationContentDigest = "edf059535c6edaf774841bc17bd6ec61eb1eeaa3cc685a913a1ed6df5125c44c"
	equivocationEvidenceID    = "605c13a5cea2ed152b9745ecd4b871e147a90a45ba0dce85a66ed041e7d82616"
	equivocationFaultID       = "daf997fbaee79f10b4cd70a13c2d90932bf28738af1bc2b79e3056d9622bb72f"

	invalidStageContentDigest = "f8325e239336cb36c0bc7eb821d9b9f437d2f02d0e2da202b35f659336177814"
	invalidStageEvidenceID    = "3f3122f6c7ab6d5776f123a3647e6fc9104b51f1dff76c1c9350bc027d2a6aee"
	invalidStageFaultID       = "6877e1952a57aae9d4eac657cff2092ac6fb6c00812d0ab823cb927450b01d0d"

	// violationWrongStage is BuilderProtocolViolation.WRONG_STAGE, this contract.
	violationWrongStage int32 = 2

	// evidenceTestPrivateKey is this contract test key the linked vectors share. It is
	// a published document fixture, not a secret.
	evidenceTestPrivateKey = "985ad41a995234c367f70942668b8e2ee2ad95513098dec4ea963b2738de745c"
)

func evidenceTaskID() []byte   { return bytes.Repeat([]byte{0x11}, 32) }
func evidenceTaskHash() []byte { return bytes.Repeat([]byte{0x22}, 32) }

func evidenceSubject() string {
	return subjectOpenVerifyPrefix + hex.EncodeToString(evidenceTaskID())
}

func testProofKey(t *testing.T) ProofKeyLookup {
	t.Helper()
	privKey := secp256k1.PrivKeyFromBytes(mustHex(t, evidenceTestPrivateKey))
	pubKey := privKey.PubKey().SerializeCompressed()
	return func(participantType int32, operator string, nonce uint64) ([]byte, ProofKeyStatus, error) {
		return pubKey, ProofKeyActive, nil
	}
}

// TestDecodeWireGoldenEnvelope is the load-bearing test of the strict
// decoder: it consumes the exact envelope bytes the contract publishes and
// asserts every value the scope projection is supposed to produce. If the pinned
// field table, the payload digest domain, the signing projection or the subject
// template were wrong, this fails.
func TestDecodeWireGoldenEnvelope(t *testing.T) {
	envelope, err := DecodeEnvelope(mustHex(t, envelopeABytes))
	if err != nil {
		t.Fatalf("decode golden envelope_a: %v", err)
	}

	fields := envelope.Fields
	if fields.SchemaVersion != 1 || fields.ChainID != evidenceChainID {
		t.Fatalf("schema/chain mismatch: %+v", fields)
	}
	if fields.Kind != KindOpenVerify || fields.PayloadType != PayloadTypeOpenVerifyV1 {
		t.Fatalf("kind %d payload_type %d, want OPEN_VERIFY/OPEN_VERIFY_V1", fields.Kind, fields.PayloadType)
	}
	if fields.SenderParticipantType != ParticipantBuilder {
		t.Fatalf("sender_participant_type %d, want BUILDER", fields.SenderParticipantType)
	}
	if fields.SenderOperatorAddress != evidenceSenderAddress {
		t.Fatalf("sender %q", fields.SenderOperatorAddress)
	}
	if fields.Subject != evidenceSubject() {
		t.Fatalf("subject %q, want %q", fields.Subject, evidenceSubject())
	}
	if fields.ServiceAuthorizationNonce != 1 || fields.MessageID != "m" ||
		fields.IssuedAtUnixMS != 1 || fields.ExpiresAtUnixMS != 2 {
		t.Fatalf("freshness/replay fields: %+v", fields)
	}
	if !bytes.Equal(fields.Nonce, make([]byte, 32)) {
		t.Fatalf("nonce %x", fields.Nonce)
	}
	if got := hex.EncodeToString(fields.PayloadDigest); got != envelopeAPayloadDigest {
		t.Fatalf("payload_digest %s, want %s", got, envelopeAPayloadDigest)
	}

	// The digest the decoder recomputed over the exact payload bytes has to be
	// the one inside the signed projection, and it has to be the document's.
	if got := PayloadDigest(envelope.Payload); hex.EncodeToString(got[:]) != envelopeAPayloadDigest {
		t.Fatalf("recomputed payload digest %x", got)
	}

	digest, err := SigningDigest(fields)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != envelopeABusSigningDigest {
		t.Fatalf("bus_signing_digest %s, want %s", got, envelopeABusSigningDigest)
	}

	scope := envelope.Scope
	if !bytes.Equal(scope.TaskID, evidenceTaskID()) {
		t.Fatalf("scope task_id %x", scope.TaskID)
	}
	if !bytes.Equal(scope.TaskHash, evidenceTaskHash()) {
		t.Fatalf("scope task_hash %x", scope.TaskHash)
	}
	if !bytes.Equal(scope.ModelID, bytes.Repeat([]byte{0x55}, 32)) {
		t.Fatalf("scope model_id %v", scope.ModelID)
	}
	if scope.VerifyRound == nil || *scope.VerifyRound != 1 {
		t.Fatalf("scope verify_round %v", scope.VerifyRound)
	}
	if scope.PayloadActor == nil || *scope.PayloadActor != evidenceWorkerAddress {
		t.Fatalf("scope payload_actor %v", scope.PayloadActor)
	}
	if scope.ExpectedSubject != evidenceSubject() {
		t.Fatalf("derived subject %q", scope.ExpectedSubject)
	}
	if envelope.OrderBytes != nil {
		t.Fatalf("OrderBytes is only set for ORDER_BROADCAST, got %d bytes", len(envelope.OrderBytes))
	}
}

// TestVerifyEvidenceEnvelopeGolden runs the proof-only profile over both golden
// envelopes, including the signature the document publishes.
func TestVerifyEvidenceEnvelopeGolden(t *testing.T) {
	opts := EvidenceVerifyOptions{ChainID: evidenceChainID, LookupKey: testProofKey(t)}
	for _, testCase := range []struct{ name, raw, digest string }{
		{"envelope_a", envelopeABytes, envelopeABusSigningDigest},
		{"envelope_b", envelopeBBytes, envelopeBBusSigningDigest},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			verified, err := VerifyEvidenceEnvelope(mustHex(t, testCase.raw), opts)
			if err != nil {
				t.Fatalf("proof-only verify: %v", err)
			}
			if got := hex.EncodeToString(verified.SigningDigest[:]); got != testCase.digest {
				t.Fatalf("signing digest %s, want %s", got, testCase.digest)
			}
		})
	}

	// A revoked binding at the same authorization nonce is still a valid proof
	// key: an emergency revoke must not destroy the ability to prove what the key
	// already signed.
	revoked := opts
	revoked.LookupKey = func(participantType int32, operator string, nonce uint64) ([]byte, ProofKeyStatus, error) {
		key, _, err := opts.LookupKey(participantType, operator, nonce)
		return key, ProofKeyRevoked, err
	}
	if _, err := VerifyEvidenceEnvelope(mustHex(t, envelopeABytes), revoked); err != nil {
		t.Fatalf("a same-nonce revoked proof key was rejected: %v", err)
	}

	// A rotation to a new nonce or key is a lookup failure, and the verifier has
	// to fail closed rather than fall back to any other binding.
	rotated := opts
	rotated.LookupKey = func(int32, string, uint64) ([]byte, ProofKeyStatus, error) {
		return nil, ProofKeyActive, errNoBinding
	}
	if _, err := VerifyEvidenceEnvelope(mustHex(t, envelopeABytes), rotated); err == nil {
		t.Fatal("a rotated binding passed")
	}

	// The proof-only profile has no wall clock. These envelopes expire at Unix
	// millisecond 2, so a profile that consulted one could never accept them.
	if _, err := VerifyEvidenceEnvelope(mustHex(t, envelopeABytes), opts); err != nil {
		t.Fatalf("an already-expired objective fact was rejected by the chain profile: %v", err)
	}
}

// TestVerifyEvidenceEnvelopeChecksHRPBeforeLookup pins the chain-facing
// acceptance gate without changing the address bytes used by SigningDigest.
func TestVerifyEvidenceEnvelopeChecksHRPBeforeLookup(t *testing.T) {
	if OperatorAddressHRPV1 != "trueopen" {
		t.Fatalf("OperatorAddressHRPV1=%q, want trueopen", OperatorAddressHRPV1)
	}
	raw := mustHex(t, envelopeABytes)
	codec, err := OperatorAddressCodecBytes(evidenceSenderAddress)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := bech32.EncodeFromBase256("cosmos", codec)
	if err != nil {
		t.Fatal(err)
	}
	short, err := bech32.EncodeFromBase256("trueopen", codec[:len(codec)-1])
	if err != nil {
		t.Fatal(err)
	}

	foreignRaw := replaceStringField(t, raw, 6, evidenceSenderAddress, foreign)
	shortRaw := replaceStringField(t, raw, 6, evidenceSenderAddress, short)
	for _, testCase := range []struct {
		name string
		raw  []byte
	}{
		{"foreign address HRP", foreignRaw},
		{"wrong address codec size", shortRaw},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			lookups := 0
			opts := EvidenceVerifyOptions{
				ChainID: evidenceChainID,
				LookupKey: func(int32, string, uint64) ([]byte, ProofKeyStatus, error) {
					lookups++
					return nil, ProofKeyActive, nil
				},
			}
			if _, err := VerifyEvidenceEnvelope(testCase.raw, opts); err == nil {
				t.Fatal("accepted")
			}
			if lookups != 0 {
				t.Fatalf("proof key lookup ran %d time(s) before HRP rejection", lookups)
			}
		})
	}
}

func replaceStringField(t *testing.T, raw []byte, number uint32, old, replacement string) []byte {
	t.Helper()
	encodedOld := encodeBytesField(number, []byte(old))
	index := bytes.Index(raw, encodedOld)
	if index < 0 {
		t.Fatalf("field %d was not found", number)
	}
	encodedReplacement := encodeBytesField(number, []byte(replacement))
	out := make([]byte, 0, len(raw)-len(encodedOld)+len(encodedReplacement))
	out = append(out, raw[:index]...)
	out = append(out, encodedReplacement...)
	out = append(out, raw[index+len(encodedOld):]...)
	return out
}

var errNoBinding = errBinding{}

type errBinding struct{}

func (errBinding) Error() string { return "no current binding at that authorization nonce" }

// TestEvidenceIdentityGolden reproduces both published linked vectors.
func TestEvidenceIdentityGolden(t *testing.T) {
	digestA := mustHex(t, envelopeABusSigningDigest)
	digestB := mustHex(t, envelopeBBusSigningDigest)

	content, err := EquivocationDigest(EquivocationContent{DigestA: digestA, DigestB: digestB})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(content[:]); got != equivocationContentDigest {
		t.Fatalf("equivocation content digest %s, want %s", got, equivocationContentDigest)
	}
	assertIdentity(t, "equivocation", content, EvidenceKindProposalEquivocation,
		equivocationEvidenceID, equivocationFaultID)

	// Swapping the two envelopes must not change the identity: the submitter does
	// not get to pick which order produces which evidence id.
	swapped, err := EquivocationDigest(EquivocationContent{DigestA: digestB, DigestB: digestA})
	if err != nil {
		t.Fatal(err)
	}
	if swapped != content {
		t.Fatalf("swapping the envelopes changed the content digest: %x vs %x", swapped, content)
	}

	stage, err := InvalidStageDigest(InvalidStageContent{SigningDigest: digestA, Violation: violationWrongStage})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(stage[:]); got != invalidStageContentDigest {
		t.Fatalf("invalid stage content digest %s, want %s", got, invalidStageContentDigest)
	}
	assertIdentity(t, "invalid stage", stage, EvidenceKindInvalidStageSubmission,
		invalidStageEvidenceID, invalidStageFaultID)
}

func assertIdentity(t *testing.T, label string, content [32]byte, kind int32, wantEvidenceID, wantFaultID string) {
	t.Helper()
	evidenceID, err := EvidenceID(evidenceChainID, evidenceSenderAddress, kind, evidenceTaskID(), content)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(evidenceID[:]); got != wantEvidenceID {
		t.Fatalf("%s evidence_id %s, want %s", label, got, wantEvidenceID)
	}
	faultID, err := FaultID(evidenceChainID, evidenceSenderAddress, kind, evidenceTaskID(), content)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(faultID[:]); got != wantFaultID {
		t.Fatalf("%s fault_id %s, want %s", label, got, wantFaultID)
	}
	if evidenceID == faultID {
		t.Fatal("evidence_id and fault_id must be distinct values under different domains")
	}
}

// TestEvidenceIdentityIgnoresRawSignature is the invariant of this contract
// that the identity must not move when a signature is replaced by another valid
// low-S signature over the same digest. The identity is built from the signing
// digest alone, so re-signing cannot fork one fault into two.
func TestEvidenceIdentityIgnoresRawSignature(t *testing.T) {
	raw := mustHex(t, envelopeABytes)
	first, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SigningDigest(first.Fields)
	if err != nil {
		t.Fatal(err)
	}

	// A second signature over the same digest, produced by a different key. It is
	// a different 64-byte value over an identical digest, which is the only thing
	// the identity is allowed to depend on.
	other := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{0x07}, 32))
	second := SignDigest(other, digest)
	if bytes.Equal(second, first.Signature) {
		t.Fatal("the two signatures are identical, so this proves nothing")
	}

	contentFirst, err := EquivocationDigest(EquivocationContent{
		DigestA: digest[:], DigestB: mustHex(t, envelopeBBusSigningDigest)})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(contentFirst[:]); got != equivocationContentDigest {
		t.Fatalf("content digest moved with the signature: %s", got)
	}
}

// TestEquivocationPreconditions covers what separates an equivocation from a
// retry and from two unrelated messages.
func TestEquivocationPreconditions(t *testing.T) {
	opts := EvidenceVerifyOptions{ChainID: evidenceChainID, LookupKey: testProofKey(t)}
	a, err := VerifyEvidenceEnvelope(mustHex(t, envelopeABytes), opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := VerifyEvidenceEnvelope(mustHex(t, envelopeBBytes), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := EquivocationPreconditions(a, b); err != nil {
		t.Fatalf("the golden equivocation pair was rejected: %v", err)
	}

	// The same envelope twice is a legitimate retry, not an equivocation.
	err = EquivocationPreconditions(a, a)
	if err == nil {
		t.Fatal("one envelope submitted twice was accepted as an equivocation")
	}
	if !strings.Contains(err.Error(), "retry") {
		t.Fatalf("retry reported as %v", err)
	}

	// Two envelopes that differ in a field the pair is required to share are two
	// messages, not one conflict.
	divergent := b
	divergent.Fields.MessageID = "different"
	if err := EquivocationPreconditions(a, divergent); err == nil {
		t.Fatal("envelopes with different message_id were accepted as one equivocation")
	}
}

// TestEquivocationPreconditionsIdentifySenderByCodecBytes covers the evasion the
// address text allows and the decoded bytes do not. bech32 pins the spelling of
// a given prefix but not the prefix itself, so one key spelled trueopen1... and
// cosmos1... decodes to the same 20 bytes. The proof-only entry rejects the
// foreign HRP before lookup; this low-level precondition still compares the
// same codec identity used by the signature, content digest and IDs.
func TestEquivocationPreconditionsIdentifySenderByCodecBytes(t *testing.T) {
	opts := EvidenceVerifyOptions{ChainID: evidenceChainID, LookupKey: testProofKey(t)}
	a, err := VerifyEvidenceEnvelope(mustHex(t, envelopeABytes), opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := VerifyEvidenceEnvelope(mustHex(t, envelopeBBytes), opts)
	if err != nil {
		t.Fatal(err)
	}

	codec, err := OperatorAddressCodecBytes(a.Fields.SenderOperatorAddress)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := bech32.EncodeFromBase256("cosmos", codec)
	if err != nil {
		t.Fatal(err)
	}
	if foreign == a.Fields.SenderOperatorAddress {
		t.Fatal("the two spellings are identical, so this proves nothing")
	}

	// Only the spelling changes: the same key, the same conflicting pair.
	b.Fields.SenderOperatorAddress = foreign
	if err := EquivocationPreconditions(a, b); err != nil {
		t.Fatalf("one sender in two bech32 prefixes was read as two senders: %v", err)
	}

	// A genuinely different key must still separate the two envelopes.
	other := make([]byte, len(codec))
	copy(other, codec)
	other[0] ^= 0xFF
	elsewhere, err := bech32.EncodeFromBase256("trueopen", other)
	if err != nil {
		t.Fatal(err)
	}
	b.Fields.SenderOperatorAddress = elsewhere
	if err := EquivocationPreconditions(a, b); err == nil {
		t.Fatal("two different operators were accepted as one equivocation")
	}
}

// TestEvidenceReservedTagIsNotAttributable pins the permanently reserved oneof
// tag. The wire API keeps OBJECTIVE_MISSED_DUTY as a Keeper-internal
// derivation, so the public branch must not be revivable by number.
func TestEvidenceReservedTagIsNotAttributable(t *testing.T) {
	for _, tag := range []uint32{EvidenceTagEquivocation, EvidenceTagInvalidStageSubmission, EvidenceTagDataUnavailable} {
		if _, err := EvidenceKindForTag(tag); err != nil {
			t.Fatalf("active tag %d rejected: %v", tag, err)
		}
	}
	for _, tag := range []uint32{0, 1, 4, 6} {
		if _, err := EvidenceKindForTag(tag); err == nil {
			t.Fatalf("tag %d is not an active branch but was accepted", tag)
		}
	}
}

func TestEvidenceIdentityRejectsUnusableInput(t *testing.T) {
	content := [32]byte{1}
	operatorBytes, err := OperatorAddressCodecBytes(evidenceSenderAddress)
	if err != nil {
		t.Fatal(err)
	}
	foreignOperator, err := bech32.EncodeFromBase256("cosmos", operatorBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name     string
		chainID  string
		operator string
		kind     int32
		scopeID  []byte
	}{
		{"no chain id", "", evidenceSenderAddress, EvidenceKindProposalEquivocation, evidenceTaskID()},
		{"bad operator", evidenceChainID, "not-an-address", EvidenceKindProposalEquivocation, evidenceTaskID()},
		{"foreign operator HRP", evidenceChainID, foreignOperator, EvidenceKindProposalEquivocation, evidenceTaskID()},
		{"unspecified kind", evidenceChainID, evidenceSenderAddress, EvidenceKindUnspecified, evidenceTaskID()},
		{"unknown kind", evidenceChainID, evidenceSenderAddress, 99, evidenceTaskID()},
		{"short scope id", evidenceChainID, evidenceSenderAddress, EvidenceKindProposalEquivocation, []byte{1, 2, 3}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := EvidenceID(testCase.chainID, testCase.operator, testCase.kind, testCase.scopeID, content); err == nil {
				t.Fatal("accepted")
			}
			if _, err := FaultID(testCase.chainID, testCase.operator, testCase.kind, testCase.scopeID, content); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	if _, err := EquivocationDigest(EquivocationContent{
		DigestA: evidenceTaskID(), DigestB: evidenceTaskID()}); err == nil {
		t.Fatal("two identical signing digests were accepted as an equivocation")
	}
	if _, err := InvalidStageDigest(InvalidStageContent{
		SigningDigest: evidenceTaskID(), Violation: 0}); err == nil {
		t.Fatal("an unspecified violation was accepted")
	}
}

// dataUnavailableContentDigest is an implementation pin, not a specification
// vector: this contract publishes linked vectors for tags 2 and 3 only, so there is no
// authored value to reproduce for tag 5. Recording the digest here still buys
// the thing a vector buys - a silent reordering or reframing of the three
// selected fields becomes a failing test rather than a fork between two chains
// that both believe they implement the same public contract. If a later tag 5
// vector and it disagrees with this line, the implementation must be corrected.
const dataUnavailableContentDigest = "286fdbb872aea2bfeac8ce30bd7a770e105d738d4e51c929ad5f9efd57abd354"

// TestDataUnavailableDigest covers the tag 5 branch, which carries stable
// primary keys only: the Keeper reloads and recomputes the deadline, the
// accepted version, the report hashes and the verdict, so none of them may
// enter the identity.
func TestDataUnavailableDigest(t *testing.T) {
	base := DataUnavailableContent{
		TaskID: evidenceTaskID(), VerifyRound: 1, BuilderOperator: evidenceSenderAddress}
	operatorBytes, err := OperatorAddressCodecBytes(evidenceSenderAddress)
	if err != nil {
		t.Fatal(err)
	}
	foreignOperator, err := bech32.EncodeFromBase256("cosmos", operatorBytes)
	if err != nil {
		t.Fatal(err)
	}

	content, err := DataUnavailableDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(content[:]); got != dataUnavailableContentDigest {
		t.Fatalf("data unavailable content digest %s, want %s", got, dataUnavailableContentDigest)
	}
	assertIdentityIsWellFormed(t, "data unavailable", content, EvidenceKindObjectiveDataUnavailable)

	// The same three values under another branch's tag must not collide, or one
	// unavailability report could be replayed as a different fault.
	stage, err := InvalidStageDigest(InvalidStageContent{
		SigningDigest: base.TaskID, Violation: violationWrongStage})
	if err != nil {
		t.Fatal(err)
	}
	if stage == content {
		t.Fatal("two oneof branches produced one content digest")
	}

	// Every selected field has to reach the digest. A field that is framed but
	// never varied would look correct in one golden value and still be dropped.
	for _, variant := range []struct {
		name    string
		content DataUnavailableContent
	}{
		{"task_id", DataUnavailableContent{
			TaskID: bytes.Repeat([]byte{0x22}, 32), VerifyRound: base.VerifyRound,
			BuilderOperator: base.BuilderOperator}},
		{"builder_operator", DataUnavailableContent{
			TaskID: base.TaskID, VerifyRound: base.VerifyRound,
			BuilderOperator: "trueopen15x328f9956n632d24wk2mt40kzcm9va5vw5e0a"}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			other, err := DataUnavailableDigest(variant.content)
			if err != nil {
				t.Fatal(err)
			}
			if other == content {
				t.Fatalf("changing %s did not change the content digest", variant.name)
			}
		})
	}

	for _, testCase := range []struct {
		name    string
		content DataUnavailableContent
	}{
		{"short task id", DataUnavailableContent{
			TaskID: []byte{1, 2, 3}, VerifyRound: 1, BuilderOperator: evidenceSenderAddress}},
		{"empty task id", DataUnavailableContent{
			VerifyRound: 1, BuilderOperator: evidenceSenderAddress}},
		{"zero round", DataUnavailableContent{
			TaskID: evidenceTaskID(), VerifyRound: 0, BuilderOperator: evidenceSenderAddress}},
		{"challenge round", DataUnavailableContent{
			TaskID: evidenceTaskID(), VerifyRound: 2, BuilderOperator: evidenceSenderAddress}},
		{"bad operator", DataUnavailableContent{
			TaskID: evidenceTaskID(), VerifyRound: 1, BuilderOperator: "not-an-address"}},
		{"foreign operator HRP", DataUnavailableContent{
			TaskID: evidenceTaskID(), VerifyRound: 1, BuilderOperator: foreignOperator}},
		{"empty operator", DataUnavailableContent{
			TaskID: evidenceTaskID(), VerifyRound: 1}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := DataUnavailableDigest(testCase.content); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// assertIdentityIsWellFormed is assertIdentity for a branch with no published
// evidence_id/fault_id vector: the values cannot be checked against this contract, but
// they must still derive and must still be separated by domain.
func assertIdentityIsWellFormed(t *testing.T, label string, content [32]byte, kind int32) {
	t.Helper()
	evidenceID, err := EvidenceID(evidenceChainID, evidenceSenderAddress, kind, evidenceTaskID(), content)
	if err != nil {
		t.Fatalf("%s evidence_id: %v", label, err)
	}
	faultID, err := FaultID(evidenceChainID, evidenceSenderAddress, kind, evidenceTaskID(), content)
	if err != nil {
		t.Fatalf("%s fault_id: %v", label, err)
	}
	if evidenceID == faultID {
		t.Fatalf("%s evidence_id and fault_id must be distinct values under different domains", label)
	}
}

// TestMaxBuilderProtocolViolationMatchesTheEnum keeps the bound in evidence.go
// from drifting away from the registry it classifies. A newly numbered value
// must reach this review point and be explicitly classified; growing the enum
// never activates it implicitly.
func TestMaxBuilderProtocolViolationMatchesTheEnum(t *testing.T) {
	const source = "../proto/task/v1/builder_evidence.proto"
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^\s*BUILDER_PROTOCOL_VIOLATION_[A-Z0-9_]+\s*=\s*(\d+)\s*;`)
	matches := pattern.FindAllStringSubmatch(string(raw), -1)
	if len(matches) < 2 {
		t.Fatalf("found %d BuilderProtocolViolation values in %s; the pattern no longer matches the source", len(matches), source)
	}
	highest := int32(-1)
	for _, match := range matches {
		value, err := strconv.ParseInt(match[1], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		if int32(value) > highest {
			highest = int32(value)
		}
	}
	if highest != maxBuilderProtocolViolation {
		t.Fatalf("maxBuilderProtocolViolation is %d but the enum's highest value is %d",
			maxBuilderProtocolViolation, highest)
	}

	if _, err := InvalidStageDigest(InvalidStageContent{
		SigningDigest: make([]byte, 32), Violation: highest + 1,
	}); err == nil {
		t.Fatalf("accepted violation %d, which the closed registry does not name", highest+1)
	}
}

func TestOnlyFrozenBuilderProtocolViolationsAreActive(t *testing.T) {
	for violation := int32(0); violation <= maxBuilderProtocolViolation+1; violation++ {
		wantActive := violation == ViolationWrongTaskScope || violation == ViolationWrongStage
		if got := IsActiveBuilderProtocolViolation(violation); got != wantActive {
			t.Errorf("IsActiveBuilderProtocolViolation(%d) = %v, want %v", violation, got, wantActive)
		}
		err := ValidateActiveBuilderProtocolViolation(violation)
		if wantActive && err != nil {
			t.Errorf("active violation %d rejected: %v", violation, err)
		}
		if !wantActive && err == nil {
			t.Errorf("inactive violation %d accepted", violation)
		}
	}

	for violation := ViolationWrongBuilderSet; violation <= maxBuilderProtocolViolation; violation++ {
		if _, err := InvalidStageDigest(InvalidStageContent{
			SigningDigest: evidenceTaskID(), Violation: violation,
		}); err == nil {
			t.Errorf("NON_ACTIVE violation %d produced a content digest", violation)
		}
	}
}
