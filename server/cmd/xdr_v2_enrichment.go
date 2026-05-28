package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type enrichmentContext struct {
	AssetImportance   string
	AssetRiskLevel    string
	VulnCount         int
	VulnHighCount     int
	IdentityPrivilege string
	AgentDisplayName  string

	MissingFields []string
}

func enrichCanonicalEvent(ctx context.Context, event *models.CanonicalEventV2, config *Config) *models.EnrichmentSnapshotV2 {
	snapshot := &models.EnrichmentSnapshotV2{
		TenantID: event.TenantID,
		EventUID: event.EventUID,
	}

	ectx := &enrichmentContext{}

	loadAssetContext(ctx, event, config, ectx)
	loadIdentityContext(ctx, event, config, ectx)

	snapshot.AssetImportance = ectx.AssetImportance
	snapshot.AssetRiskLevel = ectx.AssetRiskLevel
	snapshot.VulnCount = ectx.VulnCount
	snapshot.VulnHighCount = ectx.VulnHighCount
	snapshot.IdentityPrivilege = ectx.IdentityPrivilege
	snapshot.AgentDisplayName = ectx.AgentDisplayName
	snapshot.EnrichmentErrors = ectx.MissingFields

	applyEnrichmentScores(event, ectx)

	return snapshot
}

func loadAssetContext(ctx context.Context, event *models.CanonicalEventV2, config *Config, ectx *enrichmentContext) {
	if config.DBPool == nil {
		ectx.MissingFields = append(ectx.MissingFields, "db_unavailable")
		return
	}

	var row pgx.Row
	if event.HostID != "" {
		row = config.DBPool.QueryRow(ctx,
			`SELECT importance, risk_level, COALESCE(vuln_count,0), COALESCE(metadata->>'vuln_high_count','0')::int, COALESCE(display_name, agent_id) 
			 FROM hosts LEFT JOIN agents ON hosts.agent_id = agents.uuid 
			 WHERE hosts.id=$1 OR hosts.agent_id=$1`, event.HostID)
	} else if event.AgentID != "" {
		row = config.DBPool.QueryRow(ctx,
			`SELECT importance, risk_level, COALESCE(vuln_count,0), COALESCE(metadata->>'vuln_high_count','0')::int, COALESCE(display_name, agent_id) 
			 FROM hosts WHERE agent_id=$1 LIMIT 1`, event.AgentID)
	} else if event.NormalizedDstIP != "" {
		row = config.DBPool.QueryRow(ctx,
			`SELECT importance, risk_level, COALESCE(vuln_count,0), 0::int, hostname 
			 FROM hosts WHERE ip=$1 ORDER BY last_seen DESC LIMIT 1`, event.NormalizedDstIP)
	} else {
		ectx.MissingFields = append(ectx.MissingFields, "no_asset_key")
		return
	}

	var imp, risk, displayName string
	var vulnCount, vulnHigh int
	if err := row.Scan(&imp, &risk, &vulnCount, &vulnHigh, &displayName); err != nil {
		ectx.MissingFields = append(ectx.MissingFields, fmt.Sprintf("asset_scan_error: %v", err))
		return
	}

	ectx.AssetImportance = imp
	ectx.AssetRiskLevel = risk
	ectx.VulnCount = vulnCount
	ectx.VulnHighCount = vulnHigh
	ectx.AgentDisplayName = displayName
}

func loadIdentityContext(ctx context.Context, event *models.CanonicalEventV2, config *Config, ectx *enrichmentContext) {
	identity := strings.TrimSpace(event.ActorIdentity)
	if identity == "" {
		return
	}
	ectx.IdentityPrivilege = "unknown"
	if strings.EqualFold(identity, "root") || strings.EqualFold(identity, "administrator") {
		ectx.IdentityPrivilege = "superuser"
	} else if strings.Contains(strings.ToLower(identity), "admin") {
		ectx.IdentityPrivilege = "admin"
	} else if strings.HasPrefix(identity, "service_") || strings.HasPrefix(identity, "svc_") {
		ectx.IdentityPrivilege = "service"
	} else {
		ectx.IdentityPrivilege = "standard"
	}
}

func applyEnrichmentScores(event *models.CanonicalEventV2, ectx *enrichmentContext) {
	if event.ScoreDetail == nil {
		event.ScoreDetail = &models.ScoreDetailV2{}
	}

	assetImportanceWeight := map[string]float64{"critical": 12, "high": 8, "medium": 4, "low": 1, "": 0}
	assetRiskWeight := map[string]float64{"critical": 10, "high": 6, "medium": 3, "low": 1, "": 0}
	identityWeight := map[string]float64{"superuser": 10, "admin": 7, "service": 4, "standard": 2, "unknown": 1, "": 0}

	impBonus := assetImportanceWeight[ectx.AssetImportance]
	riskBonus := assetRiskWeight[ectx.AssetRiskLevel]
	identBonus := identityWeight[ectx.IdentityPrivilege]

	event.ScoreDetail.ImpactFactors = append(event.ScoreDetail.ImpactFactors,
		models.ScoreFactor{Name: "asset_importance", Value: impBonus, Source: ectx.AssetImportance, Weight: 0.15},
		models.ScoreFactor{Name: "asset_risk_level", Value: riskBonus, Source: ectx.AssetRiskLevel, Weight: 0.10},
		models.ScoreFactor{Name: "identity_privilege", Value: identBonus, Source: ectx.IdentityPrivilege, Weight: 0.10},
	)

	if ectx.VulnHighCount > 0 {
		event.ScoreDetail.ImpactFactors = append(event.ScoreDetail.ImpactFactors,
			models.ScoreFactor{Name: "high_severity_vulns", Value: float64(ectx.VulnHighCount) * 3, Source: "vuln_scan", Weight: 0.12},
		)
	}

	if len(ectx.MissingFields) > 0 {
		confPenalty := float64(len(ectx.MissingFields)) * 2
		event.ConfidenceScore = clampFloat(event.ConfidenceScore-confPenalty, 10, 100)
		event.ScoreDetail.MissingContext = ectx.MissingFields
		for _, field := range ectx.MissingFields {
			event.ScoreDetail.ConfidenceFactors = append(event.ScoreDetail.ConfidenceFactors,
				models.ScoreFactor{Name: "missing_context", Value: -2, Source: field, Weight: 0.10},
			)
		}
	}
}
