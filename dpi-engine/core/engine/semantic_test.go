package engine

import (
	"testing"

	"ly-flow-platform/dpi-engine/core/domain"
	"ly-flow-platform/dpi-engine/core/rules"
	"ly-flow-platform/dpi-engine/model"
)

func TestBuildSemanticFlowScoresSuspiciousDomainAboveBenign(t *testing.T) {
	benign := buildSemanticFlow(&model.FlowData{ID: "benign", HTTPHost: "example.com", Protocol: "tcp"}, &domain.AuditResult{Match: false, Domain: "example.com"}, nil)
	suspicious := buildSemanticFlow(&model.FlowData{ID: "suspicious", HTTPHost: "miner.bad", Protocol: "tcp"}, &domain.AuditResult{Match: true, Label: "mining", Score: 100, Domain: "miner.bad"}, nil)

	if suspicious.RiskScore <= benign.RiskScore {
		t.Fatalf("expected suspicious score > benign score, got suspicious=%d benign=%d", suspicious.RiskScore, benign.RiskScore)
	}
	if suspicious.RiskLevel == "" || suspicious.RiskLevel == "none" {
		t.Fatalf("expected suspicious risk level to be set, got %q", suspicious.RiskLevel)
	}
	if benign.RiskLevel != "none" {
		t.Fatalf("expected benign risk level none, got %q", benign.RiskLevel)
	}
}

func TestBuildSemanticFlowUsesRuleSeverity(t *testing.T) {
	semantic := buildSemanticFlow(&model.FlowData{ID: "db", Protocol: "tcp", AppProtocol: "mysql", DstPort: 3306}, nil, []*rules.Rule{{Msg: "database exploit", Category: rules.CategoryExploit, Severity: rules.SeverityCritical}})
	if semantic.RiskScore < 80 || semantic.RiskLevel != "critical" {
		t.Fatalf("expected critical semantic risk, got score=%d level=%s", semantic.RiskScore, semantic.RiskLevel)
	}
	if semantic.ThreatType != string(rules.CategoryExploit) {
		t.Fatalf("expected threat type from rule category, got %q", semantic.ThreatType)
	}
}
