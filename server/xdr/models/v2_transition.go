package models

const AttackMappingVersionV1 = "attack-mapping.v1"

var DefaultAttackTransitions = []AttackTransition{
	{FromTechnique: "T1595", FromTactic: "reconnaissance", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1046", FromTactic: "reconnaissance", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1190", FromTactic: "initial-access", ToTechnique: "T1059", ToTactic: "execution", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1078", FromTactic: "initial-access", ToTechnique: "T1548.003", ToTactic: "privilege-escalation", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1078", FromTactic: "initial-access", ToTechnique: "T1059", ToTactic: "execution", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1190", FromTactic: "initial-access", ToTechnique: "T1203", ToTactic: "execution", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1059", FromTactic: "execution", ToTechnique: "T1547", ToTactic: "persistence", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1059", FromTactic: "execution", ToTechnique: "T1068", ToTactic: "privilege-escalation", TransitionClass: TransitionAllowed, Penalty: 0.05, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1059", FromTactic: "execution", ToTechnique: "T1003", ToTactic: "credential-access", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1068", FromTactic: "privilege-escalation", ToTechnique: "T1003", ToTactic: "credential-access", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1003", FromTactic: "credential-access", ToTechnique: "T1021", ToTactic: "lateral-movement", TransitionClass: TransitionAllowed, Penalty: 0.08, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1003", FromTactic: "credential-access", ToTechnique: "T1555", ToTactic: "credential-access", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1021", FromTactic: "lateral-movement", ToTechnique: "T1059", ToTactic: "execution", TransitionClass: TransitionAllowed, Penalty: 0.05, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1021", FromTactic: "lateral-movement", ToTechnique: "T1003", ToTactic: "credential-access", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1059", FromTactic: "execution", ToTechnique: "T1071", ToTactic: "command-and-control", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1003", FromTactic: "credential-access", ToTechnique: "T1041", ToTactic: "exfiltration", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1041", FromTactic: "exfiltration", ToTechnique: "T1485", ToTactic: "impact", TransitionClass: TransitionAllowed, AttackMappingVersion: AttackMappingVersionV1},

	{FromTechnique: "T1190", FromTactic: "initial-access", ToTechnique: "T1021", ToTactic: "lateral-movement", TransitionClass: TransitionWeak, Penalty: 0.15, ConfidenceAdjust: -0.10, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1190", FromTactic: "initial-access", ToTechnique: "T1003", ToTactic: "credential-access", TransitionClass: TransitionWeak, Penalty: 0.12, ConfidenceAdjust: -0.08, AttackMappingVersion: AttackMappingVersionV1},

	{FromTechnique: "T1485", FromTactic: "impact", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionReverse, Penalty: 0.30, ConfidenceAdjust: -0.15, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1041", FromTactic: "exfiltration", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionReverse, Penalty: 0.25, ConfidenceAdjust: -0.12, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1071", FromTactic: "command-and-control", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionReverse, Penalty: 0.20, ConfidenceAdjust: -0.10, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1021", FromTactic: "lateral-movement", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionReverse, Penalty: 0.20, ConfidenceAdjust: -0.10, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1547", FromTactic: "persistence", ToTechnique: "T1190", ToTactic: "initial-access", TransitionClass: TransitionReverse, Penalty: 0.18, ConfidenceAdjust: -0.08, AttackMappingVersion: AttackMappingVersionV1},

	{FromTechnique: "T1485", FromTactic: "impact", ToTechnique: "T1595", ToTactic: "reconnaissance", TransitionClass: TransitionInvalid, Penalty: 0.40, ConfidenceAdjust: -0.20, AttackMappingVersion: AttackMappingVersionV1},
	{FromTechnique: "T1041", FromTactic: "exfiltration", ToTechnique: "T1046", ToTactic: "reconnaissance", TransitionClass: TransitionInvalid, Penalty: 0.35, ConfidenceAdjust: -0.18, AttackMappingVersion: AttackMappingVersionV1},
}

func LookupAttackTransition(fromTechnique, toTechnique, version string) *AttackTransition {
	for i := range DefaultAttackTransitions {
		t := &DefaultAttackTransitions[i]
		if t.FromTechnique == fromTechnique && t.ToTechnique == toTechnique && t.AttackMappingVersion == version {
			return t
		}
	}
	return &AttackTransition{
		FromTechnique:        fromTechnique,
		ToTechnique:          toTechnique,
		TransitionClass:      TransitionUnknown,
		Penalty:              0.10,
		ConfidenceAdjust:     -0.05,
		AttackMappingVersion: version,
	}
}

func TransitionPenalty(fromTechnique, toTechnique, version string) (float64, float64) {
	t := LookupAttackTransition(fromTechnique, toTechnique, version)
	return t.Penalty, t.ConfidenceAdjust
}
