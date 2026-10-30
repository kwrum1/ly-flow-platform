package main

import "testing"

func TestGradeEventPairStrong(t *testing.T) {
	a := map[string]interface{}{"agent_id": "host-a", "user": "alice"}
	b := map[string]interface{}{"agent_id": "host-a", "user": "alice"}
	if got := gradeEventPair(a, b); got != evidenceStrong {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairSessionIsStrong(t *testing.T) {
	a := map[string]interface{}{"session_id": "s-1", "agent_id": "host-a"}
	b := map[string]interface{}{"session_id": "s-1", "agent_id": "host-b"}
	if got := gradeEventPair(a, b); got != evidenceStrong {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairHostStageProgressionIsModerate(t *testing.T) {
	a := map[string]interface{}{"agent_id": "host-a", "stage_hint": "credential_access"}
	b := map[string]interface{}{"agent_id": "host-a", "stage_hint": "lateral_movement"}
	if got := gradeEventPair(a, b); got != evidenceModerate {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairSameUserAcrossHostsIsModerate(t *testing.T) {
	a := map[string]interface{}{"agent_id": "host-a", "user": "alice"}
	b := map[string]interface{}{"agent_id": "host-b", "user": "alice"}
	if got := gradeEventPair(a, b); got != evidenceModerate {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairCrossCategorySameVictimIsModerate(t *testing.T) {
	a := map[string]interface{}{"category": "traffic", "dst_ip": "10.0.0.9", "stage_hint": "lateral_movement"}
	b := map[string]interface{}{"category": "runtime", "agent_id": "10.0.0.9", "stage_hint": "execution"}
	if got := gradeEventPair(a, b); got != evidenceModerate {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairSameIPOnlyIsWeak(t *testing.T) {
	a := map[string]interface{}{"src_ip": "10.1.18.252", "agent_id": "host-a"}
	b := map[string]interface{}{"src_ip": "10.1.18.252", "agent_id": "host-b"}
	if got := gradeEventPair(a, b); got != evidenceWeak {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairSameSubnetIsContextOnly(t *testing.T) {
	a := map[string]interface{}{"src_ip": "10.1.18.10", "agent_id": "host-a"}
	b := map[string]interface{}{"src_ip": "10.1.18.20", "agent_id": "host-b"}
	if got := gradeEventPair(a, b); got != evidenceContext {
		t.Fatalf("got %s", got)
	}
}

func TestGradeEventPairUnrelatedIsNone(t *testing.T) {
	a := map[string]interface{}{"src_ip": "10.0.0.1", "agent_id": "host-a"}
	b := map[string]interface{}{"src_ip": "192.168.1.5", "agent_id": "host-b"}
	if got := gradeEventPair(a, b); got != evidenceNone {
		t.Fatalf("got %s", got)
	}
}

func TestChainEvidenceActionable(t *testing.T) {
	weak := []map[string]interface{}{
		{"src_ip": "10.1.18.252", "agent_id": "host-a", "category": "traffic"},
		{"src_ip": "10.1.18.252", "agent_id": "host-b", "category": "runtime"},
	}
	if chainEvidenceIsActionable(weak) {
		t.Fatal("shared source IP alone must not create an incident")
	}

	strong := []map[string]interface{}{
		{"agent_id": "host-a", "user": "alice"},
		{"agent_id": "host-a", "user": "alice"},
	}
	if !chainEvidenceIsActionable(strong) {
		t.Fatal("same host and identity must be actionable")
	}
}

func TestXDRChainCorrelatedUsesEvidenceGrade(t *testing.T) {
	weak := &xdrChainAgg{Events: []map[string]interface{}{
		{"src_ip": "10.1.18.252", "agent_id": "host-a", "category": "traffic"},
		{"src_ip": "10.1.18.252", "agent_id": "host-b", "category": "runtime"},
	}}
	if xdrChainIsCorrelated(weak) {
		t.Fatal("weak-only chain must not correlate")
	}

	strong := &xdrChainAgg{Events: []map[string]interface{}{
		{"agent_id": "host-a", "user": "alice", "category": "traffic"},
		{"agent_id": "host-a", "user": "alice", "category": "runtime"},
	}}
	if !xdrChainIsCorrelated(strong) {
		t.Fatal("strong chain must correlate")
	}
}

func TestXDRChainSingleEventKeepsExistingRule(t *testing.T) {
	event := map[string]interface{}{
		"category": "traffic", "src_ip": "10.1.1.181", "dst_ip": "10.1.18.253",
		"severity": "medium", "rule_name": "ET WEB_SPECIFIC_APPS ClarkConnect Linux proxy.php XSS Attempt",
	}
	if !xdrChainIsCorrelated(&xdrChainAgg{Events: []map[string]interface{}{event}}) {
		t.Fatal("single internal exploit attempt must stay actionable")
	}
}
