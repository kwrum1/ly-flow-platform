package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
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
			"rule_platform.freshness":   rulePlatformFreshness(ctx, cfg),
			"security_engine.alert_bus": checkSecurityEngineAlertBus(ctx, cfg),
			"xdr.evaluator":             checkXDREvaluator(ctx, cfg),
			"xdr.response_policy":       checkXDRResponsePolicy(cfg),
			"xdr.rules_dir":             checkRulesDir(resolveXDRRulesDir()),
			"xdr.rules":                 checkXDRRules(),
			"ops.backup":                checkBackupDirectory(),
		}

		status := "ok"
		for _, component := range components {
			if component.Status != "ok" {
				status = "degraded"
				break
			}
		}
		// Gate 2: capture visibility is reported separately from component
		// health so a degraded sensor is visible without pretending the API
		// itself is broken. It does not fold into the top-level status.
		capture := captureDebugPayload()

		payload := map[string]interface{}{
			"code":       0,
			"message":    "success",
			"status":     status,
			"checked_at": time.Now().UTC().Format(time.RFC3339Nano),
			"components": components,
			"capture":    capture,
			"versions":   buildVersionInfo(),
			"backup":     backupDirectoryReport(),
		}
		// Gate 1 / T0-06: report the actually queryable event window alongside
		// component health so a TTL setting cannot masquerade as retention.
		if cfg != nil && cfg.EventStorage != nil {
			if report, err := runRetentionAudit(ctx, cfg.EventStorage, time.Now().UTC()); err != nil {
				payload["retention"] = map[string]interface{}{"status": "unknown", "reason": err.Error()}
			} else {
				payload["retention"] = report
			}
			if pending, permanent, err := cfg.EventStorage.projectionRetryStats(ctx); err == nil {
				payload["projection_retry"] = map[string]interface{}{
					"pending": pending, "permanent_failed": permanent,
				}
			} else {
				payload["projection_retry"] = map[string]interface{}{"status": "unknown", "reason": err.Error()}
			}
		}
		json.NewEncoder(w).Encode(payload)
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
	state := "idle"
	if total > 0 {
		state = "flowing"
	}
	details["total_component_alerts"] = total
	details["state"] = state
	message := "component alert streams readable; no alerts yet"
	if total > 0 {
		message = "component alert streams readable"
	}
	return componentStatus{Status: status, Message: message, Details: details}
}

func checkXDREvaluator(ctx context.Context, cfg *Config) componentStatus {
	result, err := xdrActiveChainsResponse(ctx, cfg, 20)
	if err != nil {
		return componentStatus{Status: "error", Message: err.Error(), Remediation: "verify canonical event storage and versioned XDR persistence"}
	}
	health := cfg.XDRGraph.Health()
	healthStatus := strings.ToLower(asString(asMap(health)["status"]))
	status := "ok"
	state := "idle"
	switch {
	case len(result.activeChains()) > 0:
		state = "evaluating"
	case healthStatus != "" && healthStatus != "healthy":
		status = "degraded"
		state = "unhealthy"
	}
	return componentStatus{Status: status, Message: "XDR evaluator online", Details: map[string]interface{}{
		"chain_count": len(result.activeChains()),
		"state":       state,
		"health":      health,
	}}
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

// buildVersionInfo exposes the running image tags so the console can show the
// upgrade/rollback baseline without shelling out to docker.
func buildVersionInfo() map[string]interface{} {
	return map[string]interface{}{
		"server_image":   getEnv("LY_SERVER_IMAGE", "unknown"),
		"frontend_image": getEnv("LY_FRONTEND_IMAGE", "unknown"),
		"build":          getEnv("LY_BUILD_ID", ""),
	}
}

func backupDirectoryReport() map[string]interface{} {
	dir := getEnv("LYFLOW_BACKUP_DIR", "/backup")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return map[string]interface{}{"status": "unknown", "path": dir, "reason": err.Error(), "items": []interface{}{}}
	}
	items := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		items = append(items, map[string]interface{}{
			"name": entry.Name(), "size_bytes": info.Size(),
			"modified_at": info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	return map[string]interface{}{"status": "ok", "path": dir, "count": len(items), "items": items}
}

func checkBackupDirectory() componentStatus {
	report := backupDirectoryReport()
	if report["status"] != "ok" {
		return componentStatus{Status: "unknown", Message: "backup directory not mounted", Details: report}
	}
	// A freshly installed instance has an empty but writable backup directory.
	// That is a healthy state ("no backups yet"), not a degraded one. Only an
	// unreadable/missing mount is reported as unknown above.
	message := "backup directory readable"
	if asInt(report["count"]) == 0 {
		message = "backup directory ready, no backups yet"
	}
	return componentStatus{Status: "ok", Message: message, Details: report}
}
