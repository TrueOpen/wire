package bus

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cosmos/btcutil/bech32"
)

func builderEvidenceBytes(tag uint32, branch []byte) []byte {
	return join(
		varintField(1, uint64(BuilderEvidenceSchemaVersionV2)),
		encodeBytesField(tag, branch),
	)
}

func TestDecodeBuilderEvidenceV2Branches(t *testing.T) {
	envelopeA := mustHex(t, envelopeABytes)
	envelopeB := mustHex(t, envelopeBBytes)

	equivocationRaw := builderEvidenceBytes(EvidenceTagEquivocation, join(
		encodeBytesField(1, envelopeA),
		encodeBytesField(2, envelopeB),
	))
	equivocation, err := DecodeBuilderEvidenceV2(equivocationRaw)
	if err != nil {
		t.Fatalf("decode equivocation: %v", err)
	}
	if equivocation.EvidenceTag != EvidenceTagEquivocation || equivocation.Equivocation == nil ||
		equivocation.InvalidStageSubmission != nil || equivocation.DataUnavailable != nil {
		t.Fatalf("wrong equivocation projection: %+v", equivocation)
	}
	if !bytes.Equal(equivocation.Equivocation.EnvelopeA, envelopeA) ||
		!bytes.Equal(equivocation.Equivocation.EnvelopeB, envelopeB) {
		t.Fatal("equivocation did not retain exact envelope bytes")
	}
	opts := EvidenceVerifyOptions{ChainID: evidenceChainID, LookupKey: testProofKey(t)}
	verifiedA, err := VerifyEvidenceEnvelope(equivocation.Equivocation.EnvelopeA, opts)
	if err != nil {
		t.Fatalf("verify envelope_a: %v", err)
	}
	verifiedB, err := VerifyEvidenceEnvelope(equivocation.Equivocation.EnvelopeB, opts)
	if err != nil {
		t.Fatalf("verify envelope_b: %v", err)
	}
	if err := EquivocationPreconditions(verifiedA, verifiedB); err != nil {
		t.Fatalf("equivocation preconditions: %v", err)
	}

	invalidStageRaw := builderEvidenceBytes(EvidenceTagInvalidStageSubmission, join(
		encodeBytesField(1, envelopeA),
		varintField(2, uint64(ViolationWrongStage)),
	))
	invalidStage, err := DecodeBuilderEvidenceV2(invalidStageRaw)
	if err != nil {
		t.Fatalf("decode invalid-stage submission: %v", err)
	}
	if invalidStage.EvidenceTag != EvidenceTagInvalidStageSubmission || invalidStage.InvalidStageSubmission == nil ||
		invalidStage.Equivocation != nil || invalidStage.DataUnavailable != nil {
		t.Fatalf("wrong invalid-stage projection: %+v", invalidStage)
	}
	if invalidStage.InvalidStageSubmission.Violation != ViolationWrongStage ||
		!bytes.Equal(invalidStage.InvalidStageSubmission.Envelope, envelopeA) {
		t.Fatalf("wrong invalid-stage fields: %+v", invalidStage.InvalidStageSubmission)
	}
	if err := ValidateActiveBuilderProtocolViolation(invalidStage.InvalidStageSubmission.Violation); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEvidenceEnvelope(invalidStage.InvalidStageSubmission.Envelope, opts); err != nil {
		t.Fatalf("verify invalid-stage envelope: %v", err)
	}
	nonActiveRaw := builderEvidenceBytes(EvidenceTagInvalidStageSubmission, join(
		encodeBytesField(1, envelopeA),
		varintField(2, uint64(ViolationWrongBuilderSet)),
	))
	nonActive, err := DecodeBuilderEvidenceV2(nonActiveRaw)
	if err != nil {
		t.Fatalf("a structurally valid non-ACTIVE violation must reach the authority gate: %v", err)
	}
	if err := ValidateActiveBuilderProtocolViolation(nonActive.InvalidStageSubmission.Violation); err == nil ||
		!strings.Contains(err.Error(), "NON_ACTIVE") {
		t.Fatalf("NON_ACTIVE violation did not fail closed: %v", err)
	}

	// The fixed normal round is part of tag 5's stateless Wire contract. Task
	// authority still decides whether the referenced aggregate exists and is
	// eligible for application.
	dataUnavailableRaw := builderEvidenceBytes(EvidenceTagDataUnavailable, join(
		encodeBytesField(1, evidenceTaskID()),
		varintField(2, 1),
		stringField(3, evidenceSenderAddress),
	))
	dataUnavailable, err := DecodeBuilderEvidenceV2(dataUnavailableRaw)
	if err != nil {
		t.Fatalf("decode data-unavailable reference: %v", err)
	}
	if dataUnavailable.EvidenceTag != EvidenceTagDataUnavailable || dataUnavailable.DataUnavailable == nil ||
		dataUnavailable.Equivocation != nil || dataUnavailable.InvalidStageSubmission != nil {
		t.Fatalf("wrong data-unavailable projection: %+v", dataUnavailable)
	}
	if dataUnavailable.DataUnavailable.VerifyRound != 1 ||
		dataUnavailable.DataUnavailable.BuilderOperator != evidenceSenderAddress ||
		!bytes.Equal(dataUnavailable.DataUnavailable.TaskID, evidenceTaskID()) {
		t.Fatalf("wrong data-unavailable fields: %+v", dataUnavailable.DataUnavailable)
	}
	if _, err := DataUnavailableDigest(DataUnavailableContent{
		TaskID:          dataUnavailable.DataUnavailable.TaskID,
		VerifyRound:     dataUnavailable.DataUnavailable.VerifyRound,
		BuilderOperator: dataUnavailable.DataUnavailable.BuilderOperator,
	}); err != nil {
		t.Fatalf("round-1 structural reference did not produce a tag 5 digest: %v", err)
	}
}

func TestDecodeBuilderEvidenceV2RejectsMalformedOuterWire(t *testing.T) {
	validBranch := join(encodeBytesField(1, []byte{1}), encodeBytesField(2, []byte{2}))
	valid := builderEvidenceBytes(EvidenceTagEquivocation, validBranch)
	dataBranch := join(
		encodeBytesField(1, evidenceTaskID()),
		varintField(2, 1),
		stringField(3, evidenceSenderAddress),
	)

	for _, testCase := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"empty evidence", nil, "size must be"},
		{"over evidence cap", make([]byte, MaxBuilderEvidenceBytesV2+1), "size must be"},
		{"missing branch", varintField(1, 2), "exactly one"},
		{"wrong schema", join(varintField(1, 1), encodeBytesField(2, validBranch)), "schema_version"},
		{"duplicate schema", join(valid, varintField(1, 2)), "appears twice"},
		{"duplicate branch", join(valid, encodeBytesField(2, validBranch)), "appears twice"},
		{"duplicate oneof", join(valid, encodeBytesField(5, dataBranch)), "oneof"},
		{"empty branch", builderEvidenceBytes(2, nil), "branch field 2 is empty"},
		{"unknown branch", join(varintField(1, 2), encodeBytesField(6, validBranch)), "unknown field 6"},
		{"reserved tag 4", join(varintField(1, 2), encodeBytesField(4, validBranch)), "unknown field 4"},
		{"wrong wire type", join(varintField(1, 2), varintField(2, 1)), "wire type"},
		{"group", join(varintField(1, 2), []byte{0x13}), "group"},
		{"non-minimal tag", append([]byte{0x88, 0x00, 0x02}, encodeBytesField(2, validBranch)...), "minimally"},
		{"nested unknown", builderEvidenceBytes(2, join(validBranch, varintField(3, 1))), "unknown field 3"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodeBuilderEvidenceV2(testCase.raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

func TestDecodeBuilderEvidenceV2RejectsMalformedBranches(t *testing.T) {
	overEnvelopeCap := make([]byte, MaxEnvelopeBytes+1)
	operatorBytes, err := OperatorAddressCodecBytes(evidenceSenderAddress)
	if err != nil {
		t.Fatal(err)
	}
	foreignBuilder, err := bech32.EncodeFromBase256("cosmos", operatorBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"equivocation missing envelope_b", builderEvidenceBytes(2, encodeBytesField(1, []byte{1})), "envelope_b"},
		{"equivocation envelope over cap", builderEvidenceBytes(2, join(
			encodeBytesField(1, overEnvelopeCap), encodeBytesField(2, []byte{2}))), "1..1048576"},
		{"invalid stage missing envelope", builderEvidenceBytes(3, varintField(2, 2)), "envelope"},
		{"data unavailable short task", builderEvidenceBytes(5, join(
			encodeBytesField(1, []byte{1}), varintField(2, 1), stringField(3, evidenceSenderAddress))), "raw32"},
		{"data unavailable missing round", builderEvidenceBytes(5, join(
			encodeBytesField(1, evidenceTaskID()), stringField(3, evidenceSenderAddress))), "verify_round"},
		{"data unavailable zero round", builderEvidenceBytes(5, join(
			encodeBytesField(1, evidenceTaskID()), varintField(2, 0), stringField(3, evidenceSenderAddress))), "verify_round"},
		{"data unavailable challenge round", builderEvidenceBytes(5, join(
			encodeBytesField(1, evidenceTaskID()), varintField(2, 2), stringField(3, evidenceSenderAddress))), "verify_round"},
		{"data unavailable missing builder", builderEvidenceBytes(5, join(
			encodeBytesField(1, evidenceTaskID()), varintField(2, 1))), "builder_operator"},
		{"data unavailable foreign builder HRP", builderEvidenceBytes(5, join(
			encodeBytesField(1, evidenceTaskID()), varintField(2, 1), stringField(3, foreignBuilder))), "HRP"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodeBuilderEvidenceV2(testCase.raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

func TestCanonicalAndDomainSpecificSizeCaps(t *testing.T) {
	if MaxCanonicalFieldBytesV1 != 33_554_432 {
		t.Fatalf("MaxCanonicalFieldBytesV1=%d", MaxCanonicalFieldBytesV1)
	}
	if MaxPayloadBytes != MaxEnvelopeBytes {
		t.Fatalf("existing Bus strict-decoder cap moved: payload=%d envelope=%d", MaxPayloadBytes, MaxEnvelopeBytes)
	}
	if MaxEnvelopeBytes >= MaxBuilderEvidenceBytesV2 || MaxBuilderEvidenceBytesV2 >= MaxCanonicalFieldBytesV1 {
		t.Fatalf("size caps are not layered: envelope=%d evidence=%d canonical=%d",
			MaxEnvelopeBytes, MaxBuilderEvidenceBytesV2, MaxCanonicalFieldBytesV1)
	}
	if _, err := DecodeEnvelope(make([]byte, MaxEnvelopeBytes+1)); err == nil {
		t.Fatal("Bus envelope lower cap was relaxed by the canonical limit")
	}
}
