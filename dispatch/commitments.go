package dispatch

import "fmt"

const maxPoolMembers = 1_000_000

// RosterMember is the shared plain projection for both pool and roster members.
type RosterMember struct {
	Slot            uint32
	SlotVersion     uint64
	OperatorAddress string
	CandidateWeight uint64
}

func memberCommitment(members []RosterMember) ([]byte, error) {
	if len(members) > maxPoolMembers {
		return nil, fmt.Errorf("member count exceeds canonical limit")
	}
	parts := [][]byte{Uint32(uint32(len(members)))}
	operators := map[string]bool{}
	for i, member := range members {
		operator, err := AddressBytes(member.OperatorAddress)
		if err != nil {
			return nil, err
		}
		if member.SlotVersion == 0 || member.CandidateWeight == 0 || i > 0 && members[i-1].Slot >= member.Slot || operators[member.OperatorAddress] {
			return nil, fmt.Errorf("invalid or duplicate canonical member")
		}
		operators[member.OperatorAddress] = true
		parts = append(parts, FieldFrame(Uint32(member.Slot), Uint64(member.SlotVersion), operator, Uint64(member.CandidateWeight)))
	}
	return FieldFrame(parts...), nil
}

// RosterDigest commits availability without changing the full-pool draw seed.
func RosterDigest(chainID string, taskID [32]byte, referenceHeight uint64, snapshotID [32]byte, members []RosterMember) ([32]byte, error) {
	frame, err := memberCommitment(members)
	if err != nil {
		return [32]byte{}, err
	}
	return HashFields("TRUEOPEN_DISPATCH_ROSTER_V1", []byte(chainID), taskID[:], Uint64(referenceHeight), snapshotID[:], Uint32(uint32(len(members))), frame), nil
}

// ChallengeScope is the closed scope projection of one objective dispatch challenge.
// Optional identities use empty strings; unused hashes are fixed zero32.
type ChallengeScope struct {
	TaskID             [32]byte
	Kind               uint32
	DispatchRound      uint32
	AttemptRank        uint32
	VictimOperator     string
	BuilderAddress     string
	DispatchRecordHash [32]byte
	ChallengerAddress  string
}

// ChallengeID is shared across producers and readers, with kind-specific scope
// checks preventing an irrelevant field from creating a second challenge key.
func ChallengeID(chainID string, scope ChallengeScope) ([32]byte, error) {
	var victim, builder []byte
	var err error
	if scope.VictimOperator != "" {
		victim, err = AddressBytes(scope.VictimOperator)
		if err != nil {
			return [32]byte{}, err
		}
	}
	if scope.BuilderAddress != "" {
		builder, err = AddressBytes(scope.BuilderAddress)
		if err != nil {
			return [32]byte{}, err
		}
	}
	challenger, err := AddressBytes(scope.ChallengerAddress)
	if err != nil {
		return [32]byte{}, err
	}
	zeroRecord := scope.DispatchRecordHash == [32]byte{}
	valid := false
	switch scope.Kind {
	case 1:
		valid = len(victim) != 0 && len(builder) == 0 && zeroRecord && scope.AttemptRank == 0
	case 2, 4:
		valid = len(victim) == 0 && len(builder) == 0 && zeroRecord && scope.AttemptRank == 0
	case 3:
		valid = len(victim) == 0 && len(builder) == 0 && zeroRecord && scope.DispatchRound == 0
	case 5:
		valid = len(victim) == 0 && len(builder) != 0 && !zeroRecord && scope.DispatchRound == 0 && scope.AttemptRank == 0
	}
	if !valid {
		return [32]byte{}, fmt.Errorf("invalid challenge scope")
	}
	return HashFields("TRUEOPEN_DISPATCH_CHALLENGE_ID_V1", []byte(chainID), scope.TaskID[:], Uint32(scope.Kind), Uint32(scope.DispatchRound), Uint32(scope.AttemptRank), victim, builder, scope.DispatchRecordHash[:], challenger), nil
}
