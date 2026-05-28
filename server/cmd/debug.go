package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type componentStatus struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

func debugComponentsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		components := map[string]componentStatus{
			"postgres":                  checkPostgres(ctx, cfg),
			"postgres.agents_table":     checkTable(ctx, cfg, "agents"),
			"postgres.hosts_table":      checkTable(ctx, cfg, "hosts"),
			"migration.flags":           checkMigrationFlags(cfg),
			"redis":                     checkRedis(ctx, cfg),
			"redis.streams":             checkRedisStreams(ctx, cfg),
			"rule_platform.active":      checkRulePlatformActive(ctx, cfg),
			"rule_platform.sources":     checkRulePlatformSources(ctx, cfg),
			"security_engine.alert_bus": checkSecurityEngineAlertBus(ctx, cfg),
			"xdr.evaluator":             checkXDREvaluator(ctx, cfg),
			"xdr.response_policy":       checkXDRResponsePolicy(cfg),
			"xdr.rules_dir":             checkRulesDir(resolveXDRRulesDir()),
			"xdr.rules":                 checkXDRRules(),
		}

		status := "ok"
		for _, component := range components {
			if component.Status != "ok" {
				status = "degraded"
				break
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":       0,
			"message":    "success",
			"status":     status,
			"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
			"components": components,
		})
	}
}

func checkRulePlatformActive(ctx context.Context, cfg *Config) componentStatus {
	preview, err := previewSecurityBundle(ctx, cfg)
	if err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify detection_rules and rule bundle compiler"}
	}
	count := asInt(preview["rule_count"])
	status := "ok"
	if count == 0 {
		status = "degraded"
	}
	return componentStatus{Status: status, Message: "active rule bundle preview available", Details: preview}
}

func checkRulePlatformSources(ctx context.Context, cfg *Config) componentStatus {
	versions, err := loadRulePlatformVersions(ctx, cfg, "")
	if err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify rule_source_versions schema"}
	}
	latest := map[string]map[string]interface{}{}
	for _, version := range versions {
		sourceID := asString(version["source_id"])
		if sourceID == "" {
			continue
		}
		if _, ok := latest[sourceID]; !ok {
			latest[sourceID] = version
		}
	}
	status := "ok"
	if len(latest) < 5 {
		status = "degraded"
	}
	return componentStatus{Status: status, Message: "rule source sync history loaded", Details: map[string]interface{}{"source_count": len(latest), "latest": latest}}
}

func checkSecurityEngineAlertBus(ctx context.Context, cfg *Config) componentStatus {
	if cfg == nil || cfg.Redis == nil {
		return componentStatus{Status: "error", Message: "redis unavailable"}
	}
	streams := componentAlertStreams("")
	details := map[string]interface{}{}
	total := int64(0)
	for _, stream := range streams {
		length, err := cfg.Redis.XLen(ctx, stream).Result()
		if err != nil && err != redis.Nil {
			return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify ly-security-engine output streams"}
		}
		details[stream] = length
		total += length
	}
	status := "ok"
	if total == 0 {
		status = "degraded"
	}
	details["total_component_alerts"] = total
	return componentStatus{Status: status, Message: "component alert streams readable", Details: details}
}

func checkXDREvaluator(ctx context.Context, cfg *Config) componentStatus {
	events, _, err := loadXDRComponentEvents(cfg, 1000)
	if err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify events:xdr and component alert ingestion"}
	}
	chains := buildXDRChains(cfg, events, 20)
	posture := buildXDRPosture(events)
	candidates := buildXDRResponseCandidates(events, 20)
	status := "ok"
	if len(events) == 0 || len(chains) == 0 {
		status = "degraded"
	}
	return componentStatus{Status: status, Message: "XDR evaluator online", Details: map[string]interface{}{"event_count": len(events), "chain_count": len(chains), "candidate_count": len(candidates), "posture": posture}}
}

func checkXDRResponsePolicy(cfg *Config) componentStatus {
	policy := loadXDRResponsePolicy(cfg)
	return componentStatus{Status: "ok", Message: "XDR response policy loaded; enforcement remains candidate-only", Details: policy.PublicSummary()}
}

func checkPostgres(ctx context.Context, cfg *Config) componentStatus {
	if cfg == nil || cfg.DBPool == nil {
		return componentStatus{Status: "error", Message: "PostgreSQL pool unavailable", Remediation: "check DB_* environment and server startup logs"}
	}
	if err := cfg.DBPool.Ping(ctx); err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify postgres container health and DB credentials"}
	}
	return componentStatus{Status: "ok", Message: "PostgreSQL reachable"}
}

func checkTable(ctx context.Context, cfg *Config, table string) componentStatus {
	if cfg == nil || cfg.DBPool == nil {
		return componentStatus{Status: "error", Message: "PostgreSQL pool unavailable", Remediation: "check DB_* environment and server startup logs"}
	}
	var regclass string
	if err := cfg.DBPool.QueryRow(ctx, "SELECT COALESCE(to_regclass('public.' || $1)::text, '')", table).Scan(&regclass); err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify database connectivity"}
	}
	if regclass == "" {
		return componentStatus{Status: "error", Message: table + " table missing", Remediation: "apply runtime schema or recreate compose postgres volume after init SQL update"}
	}
	return componentStatus{Status: "ok", Message: table + " table exists", Details: map[string]interface{}{"table": regclass}}
}

func checkRedis(ctx context.Context, cfg *Config) componentStatus {
	if cfg == nil || cfg.Redis == nil {
		return componentStatus{Status: "error", Message: "Redis client unavailable", Remediation: "check REDIS_ADDR and server startup logs"}
	}
	if err := cfg.Redis.Ping(ctx).Err(); err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify redis container health and network"}
	}
	return componentStatus{Status: "ok", Message: "Redis reachable"}
}

func checkRedisStreams(ctx context.Context, cfg *Config) componentStatus {
	if cfg == nil || cfg.Redis == nil {
		return componentStatus{Status: "error", Message: "Redis client unavailable", Remediation: "check REDIS_ADDR and server startup logs"}
	}
	streams := []string{"flows:raw", "telemetry:traffic", "telemetry:runtime", "telemetry:rasp", "telemetry:log_audit", "alerts:dpi", "alerts:runtime", "alerts:rasp", "alerts:log_audit", "events:xdr", "alerts:xdr"}
	details := map[string]interface{}{}
	for _, stream := range streams {
		length, err := cfg.Redis.XLen(ctx, stream).Result()
		if err != nil && err != redis.Nil {
			return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify Redis stream permissions and availability"}
		}
		details[stream] = length
	}
	return componentStatus{Status: "ok", Message: "Redis streams readable", Details: details}
}

func checkMigrationFlags(cfg *Config) componentStatus {
	if cfg == nil {
		return componentStatus{Status: "error", Message: "config unavailable"}
	}
	return componentStatus{Status: "ok", Message: "detection migration flags loaded", Details: map[string]interface{}{
		"security_engine_enabled":           cfg.SecurityEngineEnabled,
		"legacy_xdr_component_matching":     cfg.LegacyXDROperatorMatching,
		"legacy_xdr_default_enabled":        false,
		"legacy_xdr_status":                 legacyStatus(cfg.LegacyXDROperatorMatching),
		"legacy_dpi_compose_profile":        "legacy-dpi",
		"legacy_dpi_default_enabled":        false,
		"rasp_automatic_injection":          cfg.RASPAutomaticInjection,
		"rasp_block_by_default":             cfg.RASPBlockDefault,
		"rule_source_show_restricted":       cfg.RuleDownloadRestrictedShown,
		"restricted_sources_default_hidden": !cfg.RuleDownloadRestrictedShown,
	}}
}

func legacyStatus(enabled bool) string {
	if enabled {
		return "explicitly_enabled_for_migration"
	}
	return "deprecated_disabled"
}

func checkRulesDir(dir string) componentStatus {
	st, err := os.Stat(dir)
	if err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "set XDR_RULES_DIR to mounted rules path such as /etc/ly/rules/xdr"}
	}
	if !st.IsDir() {
		return componentStatus{Status: "error", Message: dir + " is not a directory", Remediation: "set XDR_RULES_DIR to a directory"}
	}
	return componentStatus{Status: "ok", Message: "rules directory exists", Details: map[string]interface{}{"path": dir}}
}

func checkXDRRules() componentStatus {
	rules, err := loadXDRRulePack()
	if err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify XDR_RULES_DIR and rule YAML syntax"}
	}
	return componentStatus{Status: "ok", Message: "XDR rules loaded", Details: map[string]interface{}{"count": len(rules)}}
}
