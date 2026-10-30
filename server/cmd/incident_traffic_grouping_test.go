package main

import (
	"testing"
	"time"
)

func trafficTestHit(uid, src, victim, rule, severity string, at time.Time) trafficHit {
	return trafficHit{
		EventUID: uid, ObservedAt: at, SrcIP: src, DstIP: victim,
		Victim: victim, RuleID: rule, RuleName: "test rule", Severity: severity,
		Raw: []byte(`{"src_ip":"` + src + `"}`),
	}
}

func TestTrafficGroupingMergesVictimsByRootCause(t *testing.T) {
	now := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	hits := []trafficHit{
		trafficTestHit("e1", "10.1.18.252", "10.1.0.192", "et-1", "medium", now),
		trafficTestHit("e2", "10.1.18.252", "10.1.0.101", "et-1", "medium", now.Add(time.Second)),
		trafficTestHit("e3", "10.1.18.252", "10.1.0.152", "et-1", "high", now.Add(2*time.Second)),
	}
	candidates, withheld := buildTrafficIncidentCandidates(hits, 2)
	if withheld != 0 {
		t.Fatalf("withheld=%d, want 0", withheld)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates=%d, want 1 root-cause incident", len(candidates))
	}
	c := candidates[0]
	if c.Title != "10.1.18.252 内网横向可疑流量（3 个目标）" {
		t.Fatalf("title=%q", c.Title)
	}
	if len(c.Evidence) != 3 {
		t.Fatalf("evidence=%d, want 3", len(c.Evidence))
	}
	if c.Severity != "high" {
		t.Fatalf("severity=%q, want highest observed", c.Severity)
	}
	if c.CorrelationKey != "traffic:10.1.18.252:et-1" {
		t.Fatalf("correlation key=%q", c.CorrelationKey)
	}
}

func TestTrafficGroupingWithholdsSingleWeakHit(t *testing.T) {
	now := time.Now().UTC()
	hits := []trafficHit{trafficTestHit("e1", "10.1.1.181", "10.1.18.253", "et-1", "medium", now)}
	candidates, withheld := buildTrafficIncidentCandidates(hits, 2)
	if len(candidates) != 0 || withheld != 1 {
		t.Fatalf("candidates=%d withheld=%d, want 0/1", len(candidates), withheld)
	}
}

func TestTrafficGroupingAlwaysKeepsHighSeveritySingleHit(t *testing.T) {
	now := time.Now().UTC()
	hits := []trafficHit{trafficTestHit("e1", "10.1.1.181", "10.1.18.253", "et-1", "critical", now)}
	candidates, withheld := buildTrafficIncidentCandidates(hits, 2)
	if len(candidates) != 1 || withheld != 0 {
		t.Fatalf("candidates=%d withheld=%d, want 1/0", len(candidates), withheld)
	}
}

func TestTrafficGroupingMinVictimsOneRestoresLegacyBehaviour(t *testing.T) {
	now := time.Now().UTC()
	hits := []trafficHit{trafficTestHit("e1", "10.1.1.181", "10.1.18.253", "et-1", "medium", now)}
	candidates, withheld := buildTrafficIncidentCandidates(hits, 1)
	if len(candidates) != 1 || withheld != 0 {
		t.Fatalf("candidates=%d withheld=%d, want 1/0", len(candidates), withheld)
	}
}

func TestTrafficGroupingDeduplicatesEventUID(t *testing.T) {
	now := time.Now().UTC()
	hits := []trafficHit{
		trafficTestHit("e1", "10.1.18.252", "10.1.0.192", "et-1", "medium", now),
		trafficTestHit("e1", "10.1.18.252", "10.1.0.192", "et-1", "medium", now),
		trafficTestHit("e2", "10.1.18.252", "10.1.0.101", "et-1", "medium", now),
	}
	candidates, _ := buildTrafficIncidentCandidates(hits, 2)
	if len(candidates) != 1 {
		t.Fatalf("candidates=%d", len(candidates))
	}
	if len(candidates[0].Evidence) != 2 {
		t.Fatalf("evidence=%d, want 2 after dedupe", len(candidates[0].Evidence))
	}
}

func TestTrafficGroupingSeparatesDifferentRules(t *testing.T) {
	now := time.Now().UTC()
	hits := []trafficHit{
		trafficTestHit("e1", "10.1.18.252", "10.1.0.192", "et-1", "medium", now),
		trafficTestHit("e2", "10.1.18.252", "10.1.0.192", "et-2", "medium", now),
	}
	candidates, withheld := buildTrafficIncidentCandidates(hits, 2)
	if withheld != 2 {
		t.Fatalf("withheld=%d, want 2 (each group has one victim)", withheld)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates=%d, want 0", len(candidates))
	}
}

func TestLateralMinVictimsDefault(t *testing.T) {
	t.Setenv("LYFLOW_LATERAL_MIN_VICTIMS", "")
	if got := lateralMinVictims(); got != 2 {
		t.Fatalf("default=%d, want 2", got)
	}
	t.Setenv("LYFLOW_LATERAL_MIN_VICTIMS", "1")
	if got := lateralMinVictims(); got != 1 {
		t.Fatalf("override=%d, want 1", got)
	}
	t.Setenv("LYFLOW_LATERAL_MIN_VICTIMS", "bad")
	if got := lateralMinVictims(); got != 2 {
		t.Fatalf("invalid=%d, want 2", got)
	}
}
