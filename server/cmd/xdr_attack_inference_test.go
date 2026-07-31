package main

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestInferCanonicalAttackMapping(t *testing.T) {
	tests := []struct {
		name, source, rule, technique, tactic, stage string
	}{
		{"ssh valid account", "wazuh", "Wazuh SSHD root login 5715", "T1078", "TA0001", "initial_access"},
		{"sudo elevation", "wazuh", "Wazuh sudo privilege escalation 5402", "T1548.003", "TA0004", "privilege_escalation"},
		{"native yara", "yara", "LyFlow_Harmless_Validation", "T1204.002", "TA0002", "execution"},
		{"rasp command", "rasp", "RASP Command Execution Signal", "T1059", "TA0002", "execution"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := contracts.CanonicalSecurityEvent{EventType: "component_alert", Provenance: contracts.EventProvenance{Source: contracts.EventSource(test.source)}}
			technique, tactic, stage := inferCanonicalAttackMapping(event, map[string]interface{}{"rule_name": test.rule, "source_engine": test.source})
			if technique != test.technique || tactic != test.tactic || stage != test.stage {
				t.Fatalf("mapping=%s/%s/%s", technique, tactic, stage)
			}
		})
	}
}

func TestCanonicalEventsToGraphDropsHeartbeatAndMapsAttack(t *testing.T) {
	now := time.Now().UTC()
	makeEvent := func(id, rule string) contracts.CanonicalSecurityEvent {
		alert := migrationTestAlert(id)
		alert.SourceEngine = contracts.SourceEngineWazuh
		alert.Source = "wazuh"
		alert.RuleID = rule
		alert.RuleName = rule
		alert.Summary = rule
		event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), now)
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	graph, err := canonicalEventsToGraph([]contracts.CanonicalSecurityEvent{makeEvent("evt-login", "Wazuh SSHD root login 5715"), makeEvent("evt-heartbeat", "Log Collector Heartbeat")})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph) != 1 || graph[0].TechniqueID != "T1078" || graph[0].TacticID != "TA0001" {
		t.Fatalf("graph=%#v", graph)
	}
}

func TestCanonicalEventsToGraphReadsComponentAlertDetails(t *testing.T) {
	alert := migrationTestAlert("evt-nested-details")
	alert.Details = map[string]interface{}{
		"src_ip": "198.51.100.24", "dst_ip": "10.1.18.100",
		"stage_hint": "initial_access", "mitre_tactic": "initial_access", "mitre_technique": "T1190",
	}
	event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	graph, err := canonicalEventsToGraph([]contracts.CanonicalSecurityEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph) != 1 {
		t.Fatalf("graph length=%d", len(graph))
	}
	got := graph[0]
	if got.NormalizedSrcIP != "198.51.100.24" || got.NormalizedDstIP != "10.1.18.100" ||
		got.StageHint != "initial_access" || got.TechniqueID != "T1190" {
		t.Fatalf("nested component fields not normalized: %#v", got)
	}
}

func TestRejectedHypothesisHasNoIncidentOrResponseCandidate(t *testing.T) {
	now := time.Now().UTC()
	events := []*models.CanonicalEventV2{{EventUID: "evt-1", AgentID: "agent-1", VictimAsset: "host-1", ObservedAt: now}}
	hypotheses := []*models.ChainHypothesisV2{{HypothesisUID: "hyp-1", HypothesisStatus: models.HypothesisStatusRejected, PathNodeUIDs: []string{"node-1", "node-2"}, ChainScore: 80, Severity: "high", PathEvidence: &models.PathEvidence{Stages: []string{"initial_access", "execution"}}}}
	rows := activeXDRRows(events, hypotheses, 10)
	if len(rows) != 1 || len(rows[0].ResponseCandidates) != 0 {
		t.Fatalf("rows=%#v", rows)
	}
	if incidents := incidentsFromActiveXDR(activeXDRResult{chains: rows}); len(incidents) != 0 {
		t.Fatalf("rejected incidents=%#v", incidents)
	}
}
