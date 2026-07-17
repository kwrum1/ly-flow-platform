package testdata

import (
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

var FixedNow = time.Date(2026, 5, 16, 8, 0, 0, 0, time.UTC)

func hoursAgo(h int) time.Time { return FixedNow.Add(-time.Duration(h) * time.Hour) }
func minsAgo(m int) time.Time  { return FixedNow.Add(-time.Duration(m) * time.Minute) }

var TrueMultiStepSameHost = []models.CanonicalEventV2{
	{
		TenantID: "default", EventUID: "evt-a-001", SourceComponent: "traffic",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(2), NormalizedSrcIP: "198.51.100.10", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1190", TacticID: "initial-access", StageHint: models.StageInitialAccess, StageConfidence: 0.85,
		RiskScore: 60, ConfidenceScore: 80, EvaluationVersion: models.EvalVersionV2,
	},
	{
		TenantID: "default", EventUID: "evt-a-002", SourceComponent: "runtime",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(1), NormalizedSrcIP: "10.0.0.5", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1059", TacticID: "execution", StageHint: models.StageExecution, StageConfidence: 0.90,
		RiskScore: 75, ConfidenceScore: 85, EvaluationVersion: models.EvalVersionV2,
	},
	{
		TenantID: "default", EventUID: "evt-a-003", SourceComponent: "rasp",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: minsAgo(30), NormalizedSrcIP: "10.0.0.5", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1003", TacticID: "credential-access", StageHint: models.StageCredentialAccess, StageConfidence: 0.78,
		RiskScore: 70, ConfidenceScore: 78, EvaluationVersion: models.EvalVersionV2,
	},
}

var FalseSameSourceNoContinuity = []models.CanonicalEventV2{
	{
		TenantID: "default", EventUID: "evt-f-001", SourceComponent: "traffic",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(5), NormalizedSrcIP: "198.51.100.77", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1595", TacticID: "reconnaissance", StageHint: models.StageRecon, StageConfidence: 0.70,
		RiskScore: 30, ConfidenceScore: 70, EvaluationVersion: models.EvalVersionV2,
	},
	{
		TenantID: "default", EventUID: "evt-f-002", SourceComponent: "rasp",
		AgentID: "agent-db-02", HostID: "host-db-02", VictimAsset: "db-server-02",
		ObservedAt: hoursAgo(3), NormalizedSrcIP: "198.51.100.77", NormalizedDstIP: "10.0.0.8",
		TechniqueID: "T1059", TacticID: "execution", StageHint: models.StageExecution, StageConfidence: 0.75,
		RiskScore: 65, ConfidenceScore: 75, EvaluationVersion: models.EvalVersionV2,
	},
	{
		TenantID: "default", EventUID: "evt-f-003", SourceComponent: "log_audit",
		AgentID: "agent-cache-03", HostID: "host-cache-03", VictimAsset: "cache-server-03",
		ObservedAt: hoursAgo(1), NormalizedSrcIP: "198.51.100.77", NormalizedDstIP: "10.0.0.12",
		TechniqueID: "T1003", TacticID: "credential-access", StageHint: models.StageCredentialAccess, StageConfidence: 0.72,
		RiskScore: 55, ConfidenceScore: 72, EvaluationVersion: models.EvalVersionV2,
	},
}

var OutOfOrderKillChain = []models.CanonicalEventV2{
	{
		TenantID: "default", EventUID: "evt-o-001", SourceComponent: "runtime",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(4), NormalizedSrcIP: "198.51.100.10", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1059", TacticID: "execution", StageHint: models.StageExecution, StageConfidence: 0.88,
		RiskScore: 70, ConfidenceScore: 88, EvaluationVersion: models.EvalVersionV2,
	},
	{
		TenantID: "default", EventUID: "evt-o-002", SourceComponent: "traffic",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(3), NormalizedSrcIP: "198.51.100.10", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1190", TacticID: "initial-access", StageHint: models.StageInitialAccess, StageConfidence: 0.82,
		RiskScore: 65, ConfidenceScore: 82, EvaluationVersion: models.EvalVersionV2,
	},
}

var StaleEventDecay = []models.CanonicalEventV2{
	{
		TenantID: "default", EventUID: "evt-s-001", SourceComponent: "traffic",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(30), NormalizedSrcIP: "198.51.100.10", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1190", TacticID: "initial-access", StageHint: models.StageInitialAccess, StageConfidence: 0.80,
		RiskScore: 60, ConfidenceScore: 80, EvaluationVersion: models.EvalVersionV2,
	},
}

var CrossHostLateralMovements = []models.CanonicalEventV2{
	{
		TenantID: "default", EventUID: "evt-l-001", SourceComponent: "runtime",
		AgentID: "agent-web-01", HostID: "host-web-01", VictimAsset: "web-server-01",
		ObservedAt: hoursAgo(4), NormalizedSrcIP: "198.51.100.10", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1003", TacticID: "credential-access", StageHint: models.StageCredentialAccess, StageConfidence: 0.85,
		RiskScore: 72, ConfidenceScore: 85, EvaluationVersion: models.EvalVersionV2,
	},
	{
		TenantID: "default", EventUID: "evt-l-002", SourceComponent: "log_audit",
		AgentID: "agent-db-02", HostID: "host-db-02", VictimAsset: "db-server-02",
		ObservedAt: hoursAgo(2), NormalizedSrcIP: "10.0.0.5", NormalizedDstIP: "10.0.0.8",
		TechniqueID: "T1021", TacticID: "lateral-movement", StageHint: models.StageLateralMovement, StageConfidence: 0.82,
		RiskScore: 78, ConfidenceScore: 82, EvaluationVersion: models.EvalVersionV2,
	},
}

var MissingEnrichmentEvents = []models.CanonicalEventV2{
	{
		TenantID: "default", EventUID: "evt-m-001", SourceComponent: "traffic",
		AgentID: "", HostID: "", VictimAsset: "",
		ObservedAt: hoursAgo(1), NormalizedSrcIP: "198.51.100.10", NormalizedDstIP: "10.0.0.5",
		TechniqueID: "T1190", TacticID: "initial-access", StageHint: models.StageInitialAccess, StageConfidence: 0.60,
		RiskScore: 58, ConfidenceScore: 40, EvaluationVersion: models.EvalVersionV2,
	},
}

var TrustedProxyXFFCases = []struct {
	Name         string
	RemoteAddr   string
	XFF          string
	TrustedCIDRs []string
	Expected     string
}{
	{
		Name: "trusted-chain", RemoteAddr: "10.0.0.10",
		XFF: "198.51.100.7, 10.0.0.11", TrustedCIDRs: []string{"10.0.0.0/8"},
		Expected: "198.51.100.7",
	},
	{
		Name: "untrusted-remote-spoof", RemoteAddr: "203.0.113.9",
		XFF: "1.2.3.4", TrustedCIDRs: []string{"10.0.0.0/8"},
		Expected: "203.0.113.9",
	},
	{
		Name: "empty-xff", RemoteAddr: "10.0.0.10",
		XFF: "", TrustedCIDRs: []string{"10.0.0.0/8"},
		Expected: "10.0.0.10",
	},
}

func AllFixtures() map[string][]models.CanonicalEventV2 {
	return map[string][]models.CanonicalEventV2{
		"true_multi_step_same_host": TrueMultiStepSameHost,
		"false_same_source_no_cont": FalseSameSourceNoContinuity,
		"out_of_order_kill_chain":   OutOfOrderKillChain,
		"stale_event_decay":         StaleEventDecay,
		"cross_host_lateral":        CrossHostLateralMovements,
		"missing_enrichment":        MissingEnrichmentEvents,
	}
}
