package main

import (
	"strings"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

// evidenceGrade ranks how strongly two events support a relationship. Only
// strong and moderate evidence may promote a chain; weak coincidence is kept as
// context and must not merge unrelated entities.
type evidenceGrade string

const (
	evidenceStrong  evidenceGrade = "strong"
	evidenceModerate evidenceGrade = "moderate"
	evidenceWeak    evidenceGrade = "weak"
	evidenceContext evidenceGrade = "context"
	evidenceNone    evidenceGrade = "none"
)

func evidenceGradeRank(grade evidenceGrade) int {
	switch grade {
	case evidenceStrong:
		return 4
	case evidenceModerate:
		return 3
	case evidenceWeak:
		return 2
	case evidenceContext:
		return 1
	default:
		return 0
	}
}

// gradeEventPair classifies the relationship between two events.
func gradeEventPair(a, b map[string]interface{}) evidenceGrade {
	if a == nil || b == nil {
		return evidenceNone
	}
	agentA := strings.TrimSpace(xdrPickString(a, "agent_id"))
	agentB := strings.TrimSpace(xdrPickString(b, "agent_id"))
	userA := strings.TrimSpace(xdrPickString(a, "user", "actor_identity", "entities.user"))
	userB := strings.TrimSpace(xdrPickString(b, "user", "actor_identity", "entities.user"))
	srcA, srcB := xdrSourceIP(a), xdrSourceIP(b)
	victimA, victimB := xdrVictimEntity(a), xdrVictimEntity(b)
	catA := componentCategoryFromEvent(a)
	catB := componentCategoryFromEvent(b)
	stageA := normalizeXDRStage(xdrPickString(a, "stage_hint"))
	stageB := normalizeXDRStage(xdrPickString(b, "stage_hint"))

	sameHost := agentA != "" && agentA == agentB
	sameUser := userA != "" && userA == userB
	sameVictim := victimA != "" && victimA == victimB

	sessionA := strings.TrimSpace(xdrPickString(a, "session_id", "session"))
	sessionB := strings.TrimSpace(xdrPickString(b, "session_id", "session"))
	if sessionA != "" && sessionA == sessionB {
		return evidenceStrong
	}
	if sameHost && sameUser {
		return evidenceStrong
	}
	if sameHost && stageA != "" && stageB != "" &&
		models.StageOrder(stageB) > models.StageOrder(stageA) {
		return evidenceModerate
	}
	if sameUser {
		return evidenceModerate
	}
	if catA != "" && catB != "" && catA != catB && sameVictim {
		return evidenceModerate
	}
	if sameVictim && stageA != "" && stageB != "" && stageA != stageB {
		return evidenceModerate
	}
	if srcA != "" && srcA == srcB {
		return evidenceWeak
	}
	if sameSubnet(srcA, srcB) {
		return evidenceContext
	}
	return evidenceNone
}

// gradeChainEvents returns the strongest grade found across a chain's events and
// the reason for the strongest pair.
func gradeChainEvents(events []map[string]interface{}) evidenceGrade {
	best := evidenceNone
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if grade := gradeEventPair(events[i], events[j]); evidenceGradeRank(grade) > evidenceGradeRank(best) {
				best = grade
			}
		}
	}
	return best
}

// chainEvidenceIsActionable reports whether a multi-event chain has enough
// evidence to become an Incident. Single-event chains are handled separately by
// the caller because a single internal exploit attempt is actionable on its own.
func chainEvidenceIsActionable(events []map[string]interface{}) bool {
	grade := gradeChainEvents(events)
	return grade == evidenceStrong || grade == evidenceModerate
}

// sameSubnet compares /24 prefixes for IPv4 only; it is context, never evidence.
func sameSubnet(a, b string) bool {
	left := strings.Split(strings.TrimSpace(a), ".")
	right := strings.Split(strings.TrimSpace(b), ".")
	if len(left) != 4 || len(right) != 4 {
		return false
	}
	for i := 0; i < 3; i++ {
		if left[i] == "" || left[i] != right[i] {
			return false
		}
	}
	return true
}
