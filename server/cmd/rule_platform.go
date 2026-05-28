package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func rulePlatformSourcesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			items, err := loadRulePlatformSources(r.Context(), cfg)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "rule_sources_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items)}})
		case http.MethodPost:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_source", "Invalid request body")
				return
			}
			row, err := upsertRulePlatformSource(r.Context(), cfg, req)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "source_save_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": row})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func rulePlatformBundlesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		rows, err := loadRulePlatformBundles(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_bundles_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": rows, "total": len(rows)}})
	}
}

func rulePlatformSyncHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_sync_request", "Invalid request body")
			return
		}
		result, err := syncRulePlatformSource(r.Context(), cfg, req)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "source_sync_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": result})
	}
}

func rulePlatformCompilePreviewHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		preview, err := previewSecurityBundle(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "compile_preview_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": preview})
	}
}

func rulePlatformVersionsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		rows, err := loadRulePlatformVersions(r.Context(), cfg, strings.TrimSpace(r.URL.Query().Get("source_id")))
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_versions_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": rows, "total": len(rows)}})
	}
}

func rulePlatformRollbackHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		bundle, err := rollbackRulePlatformBundle(r.Context(), cfg, asString(req["version"]))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "bundle_rollback_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": bundle})
	}
}

func rulePlatformActiveBundleHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			bundle, err := loadActiveRuleBundle(r.Context(), cfg)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "active_bundle_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": bundle})
		case http.MethodPost:
			bundle, err := compileDefaultSecurityBundle(r.Context(), cfg)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "bundle_compile_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": bundle})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func loadRulePlatformSources(ctx context.Context, cfg *Config) ([]map[string]interface{}, error) {
	if err := ensureRuleSourceCatalog(ctx, cfg); err != nil {
		return nil, err
	}
	rows, err := cfg.DBPool.Query(ctx, `SELECT id, name, category, origin, COALESCE(license,''), COALESCE(url,''), bundled, connector, restricted, updatable, updated_at FROM rule_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, category, origin, license, url string
		var bundled, connector, restricted, updatable bool
		var updated time.Time
		if err := rows.Scan(&id, &name, &category, &origin, &license, &url, &bundled, &connector, &restricted, &updatable, &updated); err != nil {
			return nil, err
		}
		if restricted && !cfg.RuleDownloadRestrictedShown {
			continue
		}
		items = append(items, map[string]interface{}{"id": id, "source_id": id, "name": name, "category": category, "origin": origin, "license": license, "url": url, "bundled": bundled, "connector": connector, "restricted": restricted, "updatable": updatable, "updated_at": updated.Format(time.RFC3339)})
	}
	return items, rows.Err()
}

func upsertRulePlatformSource(ctx context.Context, cfg *Config, req map[string]interface{}) (map[string]interface{}, error) {
	id := firstNonEmpty(asString(req["id"]), asString(req["source_id"]))
	name := firstNonEmpty(asString(req["name"]), id)
	category := firstNonEmpty(asString(req["category"]), "rasp")
	origin := firstNonEmpty(asString(req["origin"]), "external_subscription")
	license := asString(req["license"])
	url := asString(req["url"])
	if url != "" {
		if err := validateRuleSourceURL(url); err != nil {
			return nil, err
		}
	}
	bundled := asBool(req["bundled"])
	connector := asBool(req["connector"])
	restricted := asBool(req["restricted"])
	updatable := asBool(req["updatable"])
	if id == "" {
		id = slugifyRulePlatformID(name)
	}
	_, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_sources (id, name, category, origin, license, url, bundled, connector, restricted, updatable, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, category=EXCLUDED.category, origin=EXCLUDED.origin, license=EXCLUDED.license, url=EXCLUDED.url, bundled=EXCLUDED.bundled, connector=EXCLUDED.connector, restricted=EXCLUDED.restricted, updatable=EXCLUDED.updatable, updated_at=NOW()`, id, name, category, origin, license, url, bundled, connector, restricted, updatable)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"id": id, "name": name, "category": category, "origin": origin, "license": license, "url": url, "bundled": bundled, "connector": connector, "restricted": restricted, "updatable": updatable}, nil
}

func loadRulePlatformBundles(ctx context.Context, cfg *Config) ([]map[string]interface{}, error) {
	rows, err := cfg.DBPool.Query(ctx, `SELECT version, status, bundle_hash, COALESCE(bundle_path,''), activated_at, created_at FROM rule_bundles ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var version, status, hash, path string
		var activated *time.Time
		var created time.Time
		if err := rows.Scan(&version, &status, &hash, &path, &activated, &created); err != nil {
			return nil, err
		}
		row := map[string]interface{}{"version": version, "status": status, "bundle_hash": hash, "bundle_path": path, "created_at": created.Format(time.RFC3339)}
		if activated != nil {
			row["activated_at"] = activated.Format(time.RFC3339)
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

func loadActiveRuleBundle(ctx context.Context, cfg *Config) (map[string]interface{}, error) {
	rows, err := loadRulePlatformBundles(ctx, cfg)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row["status"] == "active" {
			hydrateActiveBundleDetails(row)
			return row, nil
		}
	}
	return map[string]interface{}{"status": "none", "message": "no active bundle"}, nil
}

func hydrateActiveBundleDetails(row map[string]interface{}) {
	path := asString(row["bundle_path"])
	if strings.TrimSpace(path) == "" {
		path = "rules/security-engine/active-bundle.json"
	}
	var bundle compiledBundleFile
	if err := readJSONFile(path, &bundle); err != nil {
		_ = readJSONFile("rules/security-engine/active-bundle.json", &bundle)
	}
	counts := map[string]int{"traffic": 0, "runtime": 0, "rasp": 0, "log_audit": 0}
	for _, rule := range bundle.Rules {
		counts[string(rule.Category)]++
	}
	row["rule_count"] = len(bundle.Rules)
	row["rule_counts"] = counts
	row["rules"] = bundle.Rules
}

type compiledBundleFile struct {
	Version string                `json:"version"`
	Rules   []compiledRuntimeRule `json:"rules"`
}

type compiledRuntimeRule struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Category   string                   `json:"category"`
	Severity   string                   `json:"severity"`
	ScoreHint  int                      `json:"score_hint"`
	StageHint  string                   `json:"stage_hint,omitempty"`
	Field      string                   `json:"field,omitempty"`
	Value      string                   `json:"value,omitempty"`
	Operator   string                   `json:"operator,omitempty"`
	Regex      bool                     `json:"regex,omitempty"`
	Conditions []map[string]interface{} `json:"conditions,omitempty"`
	Window     map[string]interface{}   `json:"window,omitempty"`
	GroupBy    string                   `json:"group_by,omitempty"`
	Candidate  bool                     `json:"candidate"`
}

func previewSecurityBundle(ctx context.Context, cfg *Config) (map[string]interface{}, error) {
	if err := ensureDefaultDetectionRules(ctx, cfg); err != nil {
		return nil, err
	}
	rules, err := loadEnabledDetectionRules(ctx, cfg)
	if err != nil {
		return nil, err
	}
	bundle := compiledBundleFile{Version: "preview-" + time.Now().UTC().Format("20060102150405"), Rules: rules}
	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	counts := map[string]int{"traffic": 0, "runtime": 0, "rasp": 0, "log_audit": 0}
	for _, rule := range rules {
		counts[rule.Category]++
	}
	return map[string]interface{}{"version": bundle.Version, "bundle_hash": hex.EncodeToString(sum[:]), "rule_count": len(rules), "rule_counts": counts, "would_activate": false}, nil
}

func compileDefaultSecurityBundle(ctx context.Context, cfg *Config) (map[string]interface{}, error) {
	if err := ensureDefaultDetectionRules(ctx, cfg); err != nil {
		return nil, err
	}
	rules, err := loadEnabledDetectionRules(ctx, cfg)
	if err != nil {
		return nil, err
	}
	version := "db-active-" + time.Now().UTC().Format("20060102150405")
	bundle := compiledBundleFile{Version: version, Rules: rules}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll("rules/security-engine/compiled", 0o775); err != nil {
		return nil, err
	}
	target := filepath.Join("rules/security-engine/compiled", version+".json")
	if err := os.WriteFile(target, data, 0o664); err != nil {
		return nil, err
	}
	_ = os.Chmod(target, 0o644)
	if err := os.WriteFile("rules/security-engine/active-bundle.json", data, 0o664); err != nil {
		return nil, err
	}
	_ = os.Chmod("rules/security-engine/active-bundle.json", 0o644)
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if _, err := cfg.DBPool.Exec(ctx, `UPDATE rule_bundles SET status='inactive' WHERE status='active'`); err != nil {
		return nil, err
	}
	if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_bundles (version, status, bundle_hash, bundle_path, activated_at) VALUES ($1,'active',$2,$3,NOW()) ON CONFLICT (version) DO UPDATE SET status='active', bundle_hash=EXCLUDED.bundle_hash, bundle_path=EXCLUDED.bundle_path, activated_at=NOW()`, version, hash, target); err != nil {
		return nil, err
	}
	reloadStatus := reloadSecurityEngine(ctx, cfg, target)
	if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version, target, status, message) VALUES ($1,$2,$3,$4)`, version, "ly-security-engine", reloadStatus["status"], reloadStatus["message"]); err != nil {
		return nil, err
	}
	return map[string]interface{}{"version": version, "status": "active", "bundle_hash": hash, "bundle_path": target, "activated_at": time.Now().UTC().Format(time.RFC3339), "rule_count": len(rules), "reload": reloadStatus}, nil
}

func ensureDefaultDetectionRules(ctx context.Context, cfg *Config) error {
	data, err := os.ReadFile("rules/security-engine/default-bundle.json")
	if err != nil {
		return err
	}
	var bundle compiledBundleFile
	if err := json.Unmarshal(data, &bundle); err != nil {
		return err
	}
	_, err = cfg.DBPool.Exec(ctx, `INSERT INTO rule_sources (id, name, category, origin, license, bundled, connector, restricted, updatable, updated_at) VALUES ('lyflow-default', 'LyFlow Default Rules', 'all', 'internal', 'Apache-2.0', true, false, false, false, NOW()) ON CONFLICT (id) DO UPDATE SET updated_at=NOW()`)
	if err != nil {
		return err
	}
	for _, rule := range bundle.Rules {
		raw, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO detection_rules (id, source_id, category, name, support_level, enabled, rule_json, dedup_key, updated_at) VALUES ($1,'lyflow-default',$2,$3,'full_supported',true,$4,$5,NOW()) ON CONFLICT (id) DO UPDATE SET category=EXCLUDED.category, name=EXCLUDED.name, support_level=EXCLUDED.support_level, rule_json=EXCLUDED.rule_json, dedup_key=EXCLUDED.dedup_key, updated_at=NOW()`, rule.ID, rule.Category, rule.Name, string(raw), rule.ID); err != nil {
			return err
		}
	}
	return nil
}

func loadEnabledDetectionRules(ctx context.Context, cfg *Config) ([]compiledRuntimeRule, error) {
	rows, err := cfg.DBPool.Query(ctx, `SELECT id, category, name, support_level, rule_json::text FROM detection_rules WHERE enabled=true ORDER BY category, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []compiledRuntimeRule{}
	for rows.Next() {
		var id, category, name, support, raw string
		if err := rows.Scan(&id, &category, &name, &support, &raw); err != nil {
			return nil, err
		}
		if support == "unsupported" {
			continue
		}
		rule, err := compileDetectionRule(id, category, name, raw)
		if err != nil {
			return nil, err
		}
		if !compiledRuntimeRuleValid(rule) {
			continue
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func compiledRuntimeRuleValid(rule compiledRuntimeRule) bool {
	if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Category) == "" {
		return false
	}
	if len(rule.Conditions) == 0 {
		return runtimeConditionValid(map[string]interface{}{"field": rule.Field, "operator": rule.Operator, "value": rule.Value, "regex": rule.Regex})
	}
	for _, condition := range rule.Conditions {
		if !runtimeConditionValid(condition) {
			return false
		}
	}
	return true
}

func runtimeConditionValid(condition map[string]interface{}) bool {
	field := strings.TrimSpace(asString(condition["field"]))
	operator := strings.ToLower(firstNonEmpty(asString(condition["operator"]), "contains"))
	value := asString(condition["value"])
	supported := map[string]bool{"contains": true, "regex": true, "pcre": true, "equals": true, "eq": true, "prefix": true, "suffix": true, "exists": true, "not_equals": true, "neq": true, "not_exists": true}
	if field == "" || !supported[operator] {
		return false
	}
	if operator != "exists" && operator != "not_exists" && strings.TrimSpace(value) == "" {
		return false
	}
	if operator == "regex" || operator == "pcre" || asBool(condition["regex"]) {
		_, err := regexp.Compile(value)
		return err == nil
	}
	return true
}

func compileDetectionRule(id, category, name, raw string) (compiledRuntimeRule, error) {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return compiledRuntimeRule{}, err
	}
	if _, ok := m["schema_version"]; ok {
		return compileRuleEnvelope(id, category, name, m)
	}
	return compiledRuntimeRule{
		ID:         firstNonEmpty(asString(m["id"]), id),
		Name:       firstNonEmpty(asString(m["name"]), name),
		Category:   firstNonEmpty(asString(m["category"]), category),
		Severity:   firstNonEmpty(asString(m["severity"]), "medium"),
		ScoreHint:  firstNonZero(asInt(m["score_hint"]), 50),
		StageHint:  asString(m["stage_hint"]),
		Field:      asString(m["field"]),
		Value:      asString(m["value"]),
		Operator:   asString(m["operator"]),
		Regex:      asBool(m["regex"]),
		Conditions: mapSlice(m["conditions"]),
		Window:     mapValue(m["window"]),
		GroupBy:    asString(m["group_by"]),
		Candidate:  asBoolDefault(m["candidate"], true),
	}, nil
}

func compileRuleEnvelope(id, category, name string, m map[string]interface{}) (compiledRuntimeRule, error) {
	ruleCategory := firstNonEmpty(asString(m["category"]), category)
	spec := mapValue(m[ruleCategory])
	if len(spec) == 0 && ruleCategory == "traffic" {
		spec = mapValue(m["dpi"])
	}
	if len(spec) == 0 {
		return compiledRuntimeRule{}, fmt.Errorf("rule %s has no %s spec", id, ruleCategory)
	}
	scoring := mapValue(m["scoring"])
	classification := mapValue(m["classification"])
	response := mapValue(m["response"])
	conditions := mapSlice(spec["conditions"])
	conditions = appendCategoryGuards(ruleCategory, spec, conditions)
	return compiledRuntimeRule{
		ID:         firstNonEmpty(asString(m["id"]), id),
		Name:       firstNonEmpty(asString(m["name"]), name),
		Category:   ruleCategory,
		Severity:   firstNonEmpty(asString(scoring["severity"]), "medium"),
		ScoreHint:  firstNonZero(asInt(scoring["base_score"]), 50),
		StageHint:  asString(classification["stage"]),
		Conditions: conditions,
		Window:     mapValue(spec["window"]),
		GroupBy:    firstNonEmpty(asString(spec["group_by"]), asString(mapValue(spec["window"])["group_by"])),
		Candidate:  !strings.EqualFold(asString(response["action"]), "block"),
	}, nil
}

func appendCategoryGuards(category string, spec map[string]interface{}, conditions []map[string]interface{}) []map[string]interface{} {
	if category == "rasp" {
		if values := rulePlatformStringSlice(spec["languages"]); len(values) > 0 {
			conditions = append(conditions, map[string]interface{}{"field": "language", "operator": "equals", "value": values[0]})
		}
		if values := rulePlatformStringSlice(spec["hook_types"]); len(values) > 0 {
			conditions = append(conditions, map[string]interface{}{"field": "hook_type", "operator": "equals", "value": values[0]})
		}
	}
	if category == "log_audit" {
		if sources := rulePlatformStringSlice(spec["sources"]); len(sources) > 0 {
			conditions = append(conditions, map[string]interface{}{"field": "source", "operator": "equals", "value": sources[0]})
		}
	}
	return conditions
}

func reloadSecurityEngine(ctx context.Context, cfg *Config, bundlePath string) map[string]interface{} {
	if strings.TrimSpace(cfg.SecurityEngineReloadURL) == "" {
		return map[string]interface{}{"status": "skipped", "message": "reload URL not configured"}
	}
	enginePath := strings.TrimPrefix(bundlePath, "rules/")
	enginePath = "/app/rules/" + enginePath
	body, _ := json.Marshal(map[string]string{"path": enginePath})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.SecurityEngineReloadURL, strings.NewReader(string(body)))
	if err != nil {
		return map[string]interface{}{"status": "failed", "message": err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return map[string]interface{}{"status": "failed", "message": err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return map[string]interface{}{"status": "failed", "message": resp.Status}
	}
	return map[string]interface{}{"status": "ok", "message": enginePath}
}

func firstNonZero(value, fallback int) int {
	if value != 0 {
		return value
	}
	return fallback
}

func asInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	default:
		return 0
	}
}

func asBoolDefault(v interface{}, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return asBool(v)
}

func mapValue(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func mapSlice(v interface{}) []map[string]interface{} {
	switch items := v.(type) {
	case []map[string]interface{}:
		out := make([]map[string]interface{}, 0, len(items))
		out = append(out, items...)
		return out
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(items))
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func rulePlatformStringSlice(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := asString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func slugifyRulePlatformID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "source"
	}
	return out
}

func syncRulePlatformSource(ctx context.Context, cfg *Config, req map[string]interface{}) (map[string]interface{}, error) {
	if err := ensureRuleSourceCatalog(ctx, cfg); err != nil {
		return nil, err
	}
	sourceID := firstNonEmpty(asString(req["source_id"]), asString(req["id"]))
	if sourceID == "" {
		return nil, fmt.Errorf("source_id is required")
	}
	source, err := loadRulePlatformSource(ctx, cfg, sourceID)
	if err != nil {
		return nil, err
	}
	if asBool(source["restricted"]) && !cfg.RuleDownloadRestrictedShown {
		return nil, fmt.Errorf("source %s is restricted and hidden by license policy", sourceID)
	}
	license := strings.ToLower(asString(source["license"]))
	if isRestrictedRuleLicense(license) && !asBool(source["connector"]) && !cfg.RuleDownloadRestrictedShown {
		return nil, fmt.Errorf("source %s license %s requires user-provided connector", sourceID, asString(source["license"]))
	}
	version := firstNonEmpty(asString(req["version"]), time.Now().UTC().Format("20060102150405"))
	if asString(req["url"]) == "" {
		req["url"] = externalSourceURL(source, req)
	}
	rawRules := rulePlatformRulesFromRequestOrCatalog(sourceID, req)
	converted, report := convertRulePlatformRules(source, version, rawRules)
	if err := os.MkdirAll("rules/security-engine/sources", 0o775); err != nil {
		return nil, err
	}
	snapshot := map[string]interface{}{
		"source":             source,
		"version":            version,
		"mode":               firstNonEmpty(asString(req["mode"]), "sync_convert"),
		"synced_at":          time.Now().UTC().Format(time.RFC3339),
		"rule_count":         len(rawRules),
		"converted_count":    report.Converted,
		"deduplicated_count": report.Duplicates,
		"unsupported_count":  report.Unsupported,
		"rules":              converted,
		"report":             report,
	}
	snapshotForDisk := snapshot
	if len(rawRules) > 1000 {
		copySnapshot := make(map[string]interface{}, len(snapshot))
		for key, value := range snapshot {
			copySnapshot[key] = value
		}
		copySnapshot["rules"] = converted[:1000]
		copySnapshot["rules_truncated"] = true
		copySnapshot["rules_total"] = len(converted)
		snapshotForDisk = copySnapshot
	}
	data, err := json.MarshalIndent(snapshotForDisk, "", "  ")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	snapshotPath := filepath.Join("rules/security-engine/sources", sourceID+"-"+version+".json")
	if err := os.WriteFile(snapshotPath, data, 0o664); err != nil {
		return nil, err
	}
	if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_source_versions (source_id, version, content_hash, snapshot_path, sync_status, synced_at) VALUES ($1,$2,$3,$4,'synced',NOW()) ON CONFLICT (source_id, version, content_hash) DO UPDATE SET snapshot_path=EXCLUDED.snapshot_path, sync_status='synced', synced_at=NOW()`, sourceID, version, hash, snapshotPath); err != nil {
		return nil, err
	}
	inserted, duplicates, unsupported, err := upsertConvertedDetectionRules(ctx, cfg, sourceID, converted)
	if err != nil {
		return nil, err
	}
	report.Inserted = inserted
	report.Duplicates += duplicates
	report.Unsupported = unsupported
	return map[string]interface{}{"source_id": sourceID, "version": version, "content_hash": hash, "snapshot_path": snapshotPath, "status": "synced", "restricted": asBool(source["restricted"]), "license": asString(source["license"]), "rule_count": len(rawRules), "converted_count": report.Converted, "inserted_count": report.Inserted, "duplicate_count": report.Duplicates, "unsupported_count": report.Unsupported, "support": report.SupportCounts, "dedup_report": report.DedupGroups}, nil
}

type ruleSyncReport struct {
	Converted     int                      `json:"converted"`
	Inserted      int                      `json:"inserted"`
	Duplicates    int                      `json:"duplicates"`
	Unsupported   int                      `json:"unsupported"`
	SupportCounts map[string]int           `json:"support_counts"`
	DedupGroups   []map[string]interface{} `json:"dedup_groups,omitempty"`
}

func ensureRuleSourceCatalog(ctx context.Context, cfg *Config) error {
	catalog := []map[string]interface{}{
		{"id": "lyflow-default", "name": "LyFlow Default Rules", "category": "all", "origin": "internal", "license": "Apache-2.0", "url": "", "bundled": true, "connector": false, "restricted": false, "updatable": false},
		{"id": "lyflow-compiled-local", "name": "LyFlow Compiled Local Corpus", "category": "all", "origin": "internal", "license": "LyFlow-Internal", "url": "lyflow://rules/compiled/live", "bundled": true, "connector": false, "restricted": false, "updatable": false},
		{"id": "openrasp-derived", "name": "OpenRASP-derived Application Rules", "category": "rasp", "origin": "external_reference", "license": "Apache-2.0", "url": "https://raw.githubusercontent.com/baidu/openrasp/master/plugins/official/plugin.js", "bundled": false, "connector": true, "restricted": false, "updatable": false},
		{"id": "owasp-crs-connector", "name": "OWASP CRS Connector", "category": "rasp", "origin": "external_subscription", "license": "Apache-2.0", "url": "https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "custom-rasp-rules", "name": "Custom RASP Rules", "category": "rasp", "origin": "user_provided", "license": "User-Provided", "url": "", "bundled": false, "connector": false, "restricted": false, "updatable": true},
		{"id": "sigma-connector", "name": "Sigma Rules Connector", "category": "log_audit", "origin": "external_subscription", "license": "Detection Rule License", "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "falco-connector", "name": "Falco Rules Connector", "category": "runtime", "origin": "external_subscription", "license": "Apache-2.0", "url": "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "et-open-connector", "name": "Emerging Threats Open Connector", "category": "traffic", "origin": "external_subscription", "license": "ET Open", "url": "https://rules.emergingthreats.net/open/suricata/emerging-all.rules", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "oisf-trafficid", "name": "OISF Traffic ID", "category": "traffic", "origin": "external_subscription", "license": "MIT", "url": "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "stamus-lateral", "name": "Stamus Lateral Movement Rules", "category": "traffic", "origin": "external_subscription", "license": "GPL-3.0-or-later", "url": "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "snort-community", "name": "Snort Community Rules", "category": "traffic", "origin": "external_subscription", "license": "GPL-2.0", "url": "https://www.snort.org/downloads/community/community-rules.tar.gz", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "ptresearch-attackdetection", "name": "Positive Technologies AttackDetection", "category": "traffic", "origin": "external_subscription", "license": "Positive Technologies Custom", "url": "https://rules.ptsecurity.com/files/ptopen.rules.tar.gz", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "ip-geo-attribution", "name": "IP 地理归属更新", "category": "geoip", "origin": "external_subscription", "license": "CC-BY-SA / vendor dependent", "url": "https://github.com/Loyalsoldier/v2ray-rules-dat", "bundled": true, "connector": false, "restricted": false, "updatable": true},
		{"id": "restricted-commercial", "name": "Restricted Commercial Feed", "category": "runtime", "origin": "external_subscription", "license": "Commercial Restricted", "url": "https://example.invalid/feed", "bundled": false, "connector": true, "restricted": true, "updatable": true},
	}
	for _, row := range catalog {
		if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_sources (id, name, category, origin, license, url, bundled, connector, restricted, updatable, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, category=EXCLUDED.category, origin=EXCLUDED.origin, license=EXCLUDED.license, url=EXCLUDED.url, bundled=EXCLUDED.bundled, connector=EXCLUDED.connector, restricted=EXCLUDED.restricted, updatable=EXCLUDED.updatable, updated_at=NOW()`, row["id"], row["name"], row["category"], row["origin"], row["license"], row["url"], row["bundled"], row["connector"], row["restricted"], row["updatable"]); err != nil {
			return err
		}
		version := "catalog-" + time.Now().UTC().Format("20060102")
		raw, err := json.Marshal(row)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		hash := hex.EncodeToString(sum[:])
		snapshotPath := firstNonEmpty(asString(row["url"]), "lyflow://rules/source/"+asString(row["id"]))
		if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_source_versions (source_id, version, content_hash, snapshot_path, sync_status, synced_at) VALUES ($1,$2,$3,$4,'synced',NOW()) ON CONFLICT (source_id, version, content_hash) DO UPDATE SET snapshot_path=EXCLUDED.snapshot_path, sync_status='synced', synced_at=NOW()`, row["id"], version, hash, snapshotPath); err != nil {
			return err
		}
	}
	return nil
}

func rulePlatformRulesFromRequestOrCatalog(sourceID string, req map[string]interface{}) []map[string]interface{} {
	if rules := mapSlice(req["rules"]); len(rules) > 0 {
		return rules
	}
	if inline := asString(req["content"]); strings.TrimSpace(inline) != "" {
		return parseExternalRuleSource(sourceID, inline)
	}
	switch sourceID {
	case "lyflow-compiled-local":
		return loadLocalCompiledRuleCorpus()
	case "custom-rasp-rules":
		return []map[string]interface{}{}
	}
	sourceURL := asString(req["url"])
	if sourceURL == "" {
		return loadCachedExternalRuleSource(sourceID)
	}
	if err := validateRuleSourceURL(sourceURL); err != nil {
		return nil
	}
	checksum := firstNonEmpty(asString(req["sha256"]), asString(req["checksum"]), asString(req["content_hash"]))
	content, err := fetchExternalRuleSource(sourceID, sourceURL, checksum)
	if err != nil {
		return loadCachedExternalRuleSource(sourceID)
	}
	rules := parseExternalRuleSource(sourceID, content)
	if len(rules) == 0 {
		return loadCachedExternalRuleSource(sourceID)
	}
	return rules
}

func externalSourceURL(source map[string]interface{}, req map[string]interface{}) string {
	return firstNonEmpty(asString(req["url"]), asString(source["url"]))
}

func fetchExternalRuleSource(sourceID, sourceURL, checksum string) (string, error) {
	if err := validateRuleSourceURL(sourceURL); err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 45 * time.Second}
	req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "ly-flow-rule-connector/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("fetch %s failed: %s", sourceURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", err
	}
	if checksum != "" {
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(strings.TrimSpace(checksum), got) {
			return "", fmt.Errorf("rule source checksum mismatch: got %s", got)
		}
	}
	if err := os.MkdirAll("rules/security-engine/remote-cache", 0o775); err == nil {
		_ = os.WriteFile(filepath.Join("rules/security-engine/remote-cache", sourceID+".raw"), body, 0o664)
	}
	return decodeRuleSourceBody(body)
}

func decodeRuleSourceBody(body []byte) (string, error) {
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		defer gz.Close()
		data, err := io.ReadAll(io.LimitReader(gz, 128<<20))
		if err != nil {
			return "", err
		}
		if text, ok := readRuleTarText(data); ok {
			return text, nil
		}
		return string(data), nil
	}
	if text, ok := readRuleTarText(body); ok {
		return text, nil
	}
	return string(body), nil
}

func readRuleTarText(data []byte) (string, bool) {
	tr := tar.NewReader(bytes.NewReader(data))
	var b strings.Builder
	readAny := false
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		if header == nil || header.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.ToLower(header.Name)
		if !strings.HasSuffix(name, ".rules") && !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".txt") {
			continue
		}
		chunk, err := io.ReadAll(io.LimitReader(tr, 32<<20))
		if err != nil {
			return "", false
		}
		b.WriteByte('\n')
		b.Write(chunk)
		readAny = true
	}
	return b.String(), readAny
}

func validateRuleSourceURL(sourceURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(sourceURL))
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("rule source URL must be absolute https/http URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("rule source URL scheme %q is not allowed", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("rule source URL host is required")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("rule source URL host localhost is not allowed")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("rule source URL host lookup failed: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("rule source URL host resolves to non-public address %s", ip.String())
		}
	}
	return nil
}

func loadCachedExternalRuleSource(sourceID string) []map[string]interface{} {
	if rules := loadLatestRuleSourceSnapshot(sourceID); len(rules) > 0 {
		return rules
	}
	paths := []string{
		filepath.Join("rules/security-engine/remote-cache", sourceID+".raw"),
		defaultLocalConnectorPath(sourceID),
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return parseExternalRuleSource(sourceID, string(data))
		}
	}
	return nil
}

func loadLatestRuleSourceSnapshot(sourceID string) []map[string]interface{} {
	paths, err := filepath.Glob(filepath.Join("rules/security-engine/sources", sourceID+"-*.json"))
	if err != nil || len(paths) == 0 {
		return nil
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] > paths[j] })
	for _, path := range paths {
		var snapshot map[string]interface{}
		if err := readJSONFile(path, &snapshot); err != nil {
			continue
		}
		if rules := mapSlice(snapshot["rules"]); len(rules) > 0 {
			return rules
		}
	}
	return nil
}

func defaultLocalConnectorPath(sourceID string) string {
	switch sourceID {
	case "openrasp-derived":
		return "rules/rasp/elkeid_rasp_rules.yaml"
	case "et-open-connector":
		return "rules/suricata/et-open.rules"
	default:
		return ""
	}
}

func parseExternalRuleSource(sourceID, content string) []map[string]interface{} {
	switch sourceID {
	case "openrasp-derived":
		return parseOpenRASPRules(content)
	case "owasp-crs-connector":
		return parseOWASPCRSRules(content)
	case "sigma-connector":
		return parseSigmaRules(content)
	case "falco-connector":
		return parseFalcoRules(content)
	case "et-open-connector":
		return parseSuricataRules(content, "et-open")
	case "oisf-trafficid":
		return parseSuricataRules(content, "oisf-trafficid")
	case "stamus-lateral":
		return parseSuricataRules(content, "stamus-lateral")
	case "snort-community":
		return parseSuricataRules(content, "snort-community")
	case "ptresearch-attackdetection":
		return parseSuricataRules(content, "ptresearch-attackdetection")
	default:
		return nil
	}
}

func parseOpenRASPRules(content string) []map[string]interface{} {
	if strings.Contains(content, "rules:") && strings.Contains(content, "patterns:") {
		return parseElkeidStyleRules(content, "rasp", "openrasp")
	}
	out := []map[string]interface{}{}
	re := regexp.MustCompile(`(?m)^\s*([a-zA-Z0-9_]+)\s*:\s*\{`)
	seen := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		key := strings.TrimSpace(m[1])
		if !strings.Contains(strings.ToLower(key), "sql") && !strings.Contains(strings.ToLower(key), "command") && !strings.Contains(strings.ToLower(key), "webshell") && !strings.Contains(strings.ToLower(key), "ssrf") && !strings.Contains(strings.ToLower(key), "file") && !strings.Contains(strings.ToLower(key), "xxe") {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, openRASPRuleForAlgorithm(key))
	}
	if len(out) == 0 {
		for _, key := range []string{"sql_userinput", "sql_policy", "command_reflect", "webshell_command", "ssrf_common", "file_upload_webshell"} {
			out = append(out, openRASPRuleForAlgorithm(key))
		}
	}
	return out
}

func openRASPRuleForAlgorithm(key string) map[string]interface{} {
	lower := strings.ToLower(key)
	field, pattern, severity, stage := "query", "(?i)(union\\s+select|or\\s+1=1|sleep\\s*\\(|benchmark\\s*\\()", "high", "initial_access"
	switch {
	case strings.Contains(lower, "command"):
		field, pattern, severity, stage = "command", "(?i)(/bin/sh|bash\\s+-i|cmd\\.exe|powershell|/dev/tcp|;\\s*(id|whoami|cat))", "critical", "execution"
	case strings.Contains(lower, "webshell"):
		field, pattern, severity, stage = "payload", "(?i)(eval\\s*\\(|assert\\s*\\(|base64_decode|Runtime\\.getRuntime|ProcessBuilder)", "critical", "persistence"
	case strings.Contains(lower, "ssrf"):
		field, pattern, severity, stage = "url", "(?i)(127\\.0\\.0\\.1|169\\.254\\.169\\.254|localhost|file://|gopher://)", "high", "initial_access"
	case strings.Contains(lower, "file"):
		field, pattern, severity, stage = "path", "(?i)(\\.\\./|/etc/passwd|WEB-INF|id_rsa|\\.jsp$|\\.php$)", "high", "credential_access"
	}
	return map[string]interface{}{"id": "openrasp-" + slugifyRulePlatformID(key), "name": "OpenRASP " + key, "category": "rasp", "severity": severity, "stage_hint": stage, "field": field, "operator": "regex", "value": pattern, "source_operator": "openrasp_algorithm", "candidate": true}
}

func parseElkeidStyleRules(content, category, prefix string) []map[string]interface{} {
	var doc map[string]interface{}
	if yaml.Unmarshal([]byte(content), &doc) != nil {
		return nil
	}
	rules := mapSlice(doc["rules"])
	out := []map[string]interface{}{}
	for _, r := range rules {
		patterns := mapSlice(r["patterns"])
		conditions := []map[string]interface{}{}
		field := defaultRuleField(category)
		if category == "rasp" {
			field = fieldForRASPHook(asString(r["hook_type"]))
		}
		for _, p := range patterns {
			op := strings.ToLower(firstNonEmpty(asString(p["type"]), "contains"))
			if op == "regex" {
				conditions = append(conditions, map[string]interface{}{"field": field, "operator": "regex", "value": asString(p["value"]), "regex": true})
			} else {
				conditions = append(conditions, map[string]interface{}{"field": field, "operator": "contains", "value": asString(p["value"])})
			}
		}
		if len(conditions) == 0 {
			continue
		}
		out = append(out, map[string]interface{}{"id": prefix + "-" + asString(r["id"]), "name": firstNonEmpty(asString(r["name"]), asString(r["id"])), "category": category, "severity": firstNonEmpty(asString(r["severity"]), "medium"), "stage_hint": inferRuleStage(category, asString(r["name"])+" "+asString(r["description"])), "field": field, "operator": "contains", "value": firstNonEmpty(asString(r["name"]), asString(r["id"])), "conditions": conditions, "source_operator": "elkeid_yaml", "candidate": true})
	}
	return out
}

func fieldForRASPHook(hook string) string {
	switch strings.ToLower(hook) {
	case "sql", "db", "database":
		return "query"
	case "exec", "command", "command_exec":
		return "command"
	case "file", "file_ops", "include", "read", "write", "upload":
		return "path"
	case "request", "webshell":
		return "payload"
	case "ssrf", "http":
		return "url"
	default:
		return "payload"
	}
}

func parseOWASPCRSRules(content string) []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, block := range collectModSecurityBlocks(content) {
		id := extractRuleAttribute(block, `id:?'?([0-9]+)'?`)
		if id == "" {
			continue
		}
		msg := firstNonEmpty(extractRuleAttribute(block, `msg:'([^']+)'`), "OWASP CRS Rule "+id)
		severity := strings.ToLower(firstNonEmpty(extractRuleAttribute(block, `severity:'?([A-Z]+)'?`), "medium"))
		pattern := extractRulePattern(block)
		operator := "regex"
		if pattern == "" || strings.Contains(block, "@detectSQLi") {
			pattern = "(?i)(union\\s+select|or\\s+1=1|sleep\\s*\\(|benchmark\\s*\\(|information_schema|extractvalue|updatexml)"
		}
		out = append(out, map[string]interface{}{"id": "owasp-crs-" + id, "name": msg, "category": "rasp", "severity": severityFromCRS(severity), "stage_hint": "initial_access", "field": "payload", "operator": operator, "value": pattern, "source_operator": "modsecurity", "candidate": true})
	}
	return out
}

func collectModSecurityBlocks(content string) []string {
	lines := strings.Split(content, "\n")
	out := []string{}
	var b strings.Builder
	collecting := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "SecRule ") {
			if collecting && b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			collecting = true
		}
		if collecting {
			b.WriteString(trim)
			b.WriteByte(' ')
			if !strings.HasSuffix(trim, `\`) {
				out = append(out, b.String())
				b.Reset()
				collecting = false
			}
		}
	}
	if collecting && b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func extractRuleAttribute(block, pattern string) string {
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(block)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractRulePattern(block string) string {
	for _, pattern := range []string{`@rx\s+(.+?)(?:\\|")`, `SecRule\s+\S+\s+"([^"]+)"`} {
		re := regexp.MustCompile(pattern)
		m := re.FindStringSubmatch(block)
		if len(m) > 1 {
			return strings.TrimSpace(strings.TrimSuffix(m[1], `\`))
		}
	}
	return ""
}

func severityFromCRS(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "error":
		return "critical"
	case "warning", "warn":
		return "medium"
	case "notice":
		return "low"
	default:
		return firstNonEmpty(strings.ToLower(severity), "medium")
	}
}

func parseSigmaRules(content string) []map[string]interface{} {
	docs := splitYAMLDocuments(content)
	out := []map[string]interface{}{}
	for i, docText := range docs {
		var doc map[string]interface{}
		if yaml.Unmarshal([]byte(docText), &doc) != nil || len(doc) == 0 {
			continue
		}
		detection := mapValue(doc["detection"])
		conditions := sigmaConditions(detection)
		if len(conditions) == 0 {
			continue
		}
		category := "log_audit"
		logsource := mapValue(doc["logsource"])
		if strings.Contains(strings.ToLower(asString(logsource["category"])), "process") {
			category = "runtime"
		}
		out = append(out, map[string]interface{}{"id": "sigma-" + slugifyRulePlatformID(firstNonEmpty(asString(doc["id"]), asString(doc["title"]), fmt.Sprintf("rule-%d", i))), "name": firstNonEmpty(asString(doc["title"]), "Sigma Rule"), "category": category, "severity": sigmaLevel(asString(doc["level"])), "stage_hint": sigmaStage(stringSliceFromInterface(doc["tags"])), "field": defaultRuleField(category), "operator": "contains", "value": firstNonEmpty(asString(doc["title"]), "sigma"), "conditions": conditions, "source_operator": "sigma_yaml", "candidate": true})
	}
	return out
}

func sigmaConditions(detection map[string]interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	condition := strings.ToLower(asString(detection["condition"]))
	for key, value := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		conditions := sigmaValueConditions(value)
		if strings.TrimSpace(condition) == key || strings.Contains(condition, "1 of "+key) || strings.Contains(condition, "1 of them") {
			if regexCondition := oneOfConditionsRegex(conditions); len(regexCondition) > 0 {
				out = append(out, regexCondition)
				continue
			}
		}
		out = append(out, conditions...)
	}
	return out
}

func oneOfConditionsRegex(conditions []map[string]interface{}) map[string]interface{} {
	values := []string{}
	field := "message"
	for _, condition := range conditions {
		if asString(condition["field"]) != "" {
			field = asString(condition["field"])
		}
		if value := asString(condition["value"]); value != "" {
			values = append(values, regexp.QuoteMeta(value))
		}
	}
	if len(values) == 0 {
		return nil
	}
	return map[string]interface{}{"field": field, "operator": "regex", "value": "(?i)(" + strings.Join(values, "|") + ")", "regex": true}
}

func sigmaValueConditions(value interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	switch v := value.(type) {
	case []interface{}:
		for _, item := range v {
			if s := asString(item); s != "" {
				out = append(out, map[string]interface{}{"field": "message", "operator": "contains", "value": s})
			}
		}
	case map[string]interface{}:
		for field, raw := range v {
			mapped := mapSigmaField(field)
			op := sigmaOperator(field)
			switch x := raw.(type) {
			case []interface{}:
				for _, item := range x {
					if s := asString(item); s != "" {
						out = append(out, map[string]interface{}{"field": mapped, "operator": op, "value": s})
					}
				}
			default:
				if s := asString(x); s != "" && s != "*" {
					out = append(out, map[string]interface{}{"field": mapped, "operator": op, "value": strings.Trim(s, "*")})
				}
			}
		}
	}
	return out
}

func mapSigmaField(field string) string {
	base := strings.Split(field, "|")[0]
	switch strings.ToLower(base) {
	case "commandline", "process.command_line":
		return "cmdline"
	case "image", "process.executable":
		return "process_name"
	case "pam_message", "message", "keywords":
		return "message"
	default:
		return "message"
	}
}

func sigmaOperator(field string) string {
	if strings.Contains(field, "|endswith") {
		return "suffix"
	}
	if strings.Contains(field, "|startswith") {
		return "prefix"
	}
	return "contains"
}

func sigmaLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(level)
	default:
		return "medium"
	}
}

func sigmaStage(tags []string) string {
	joined := strings.ToLower(strings.Join(tags, " "))
	if strings.Contains(joined, "execution") || strings.Contains(joined, "t1059") {
		return "execution"
	}
	if strings.Contains(joined, "credential") || strings.Contains(joined, "t1110") {
		return "credential_access"
	}
	if strings.Contains(joined, "initial-access") || strings.Contains(joined, "initial_access") {
		return "initial_access"
	}
	return "detection"
}

func splitYAMLDocuments(content string) []string {
	parts := strings.Split(content, "\n---")
	out := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseFalcoRules(content string) []map[string]interface{} {
	var docs []map[string]interface{}
	if yaml.Unmarshal([]byte(content), &docs) != nil {
		return nil
	}
	out := []map[string]interface{}{}
	for _, item := range docs {
		name := asString(item["rule"])
		if name == "" {
			continue
		}
		condition := asString(item["condition"])
		field, pattern := falcoConditionToMatch(condition, asString(item["output"])+" "+asString(item["desc"])+" "+name)
		if pattern == "" {
			continue
		}
		out = append(out, map[string]interface{}{"id": "falco-" + slugifyRulePlatformID(name), "name": name, "category": "runtime", "severity": falcoPriority(asString(item["priority"])), "stage_hint": sigmaStage(stringSliceFromInterface(item["tags"])), "field": field, "operator": "regex", "value": pattern, "source_operator": "falco_yaml", "candidate": true})
	}
	return out
}

func falcoConditionToMatch(condition, haystack string) (string, string) {
	lower := strings.ToLower(condition + " " + haystack)
	switch {
	case strings.Contains(lower, "shell") || strings.Contains(lower, "proc.cmdline"):
		return "cmdline", "(?i)(/bin/sh|/bin/bash|bash\\s+-i|sh\\s+-i|/dev/tcp|nc\\s+-e)"
	case strings.Contains(lower, "sensitive") || strings.Contains(lower, "etc") || strings.Contains(lower, "ssh"):
		return "path", "(?i)(/etc/passwd|/etc/shadow|/root/\\.ssh|id_rsa|authorized_keys)"
	case strings.Contains(lower, "write") || strings.Contains(lower, "modify"):
		return "path", "(?i)(\\.bashrc|\\.profile|/etc/cron|/etc/ld\\.so|/etc/sudoers)"
	case strings.Contains(lower, "connect") || strings.Contains(lower, "inbound") || strings.Contains(lower, "outbound"):
		return "cmdline", "(?i)(curl|wget|nc|ncat|python.*socket|bash.*tcp)"
	default:
		return "cmdline", "(?i)" + regexp.QuoteMeta(firstKeyword(haystack))
	}
}

func firstKeyword(value string) string {
	for _, token := range strings.Fields(value) {
		token = strings.Trim(token, "()[]{}.,:%=\\\"'")
		if len(token) >= 4 {
			return token
		}
	}
	return "process"
}

func falcoPriority(priority string) string {
	switch strings.ToLower(priority) {
	case "emergency", "alert", "critical":
		return "critical"
	case "error", "warning":
		return "high"
	case "notice":
		return "medium"
	default:
		return "low"
	}
}

func parseSuricataRules(content, prefix string) []map[string]interface{} {
	out := []map[string]interface{}{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "(") || !strings.Contains(line, ")") {
			continue
		}
		openIdx := strings.Index(line, "(")
		closeIdx := strings.LastIndex(line, ")")
		if openIdx < 0 || closeIdx <= openIdx {
			continue
		}
		rule := parseSuricataRuleLine(line[openIdx+1:closeIdx], prefix)
		if len(rule) > 0 {
			out = append(out, rule)
			if len(out) >= 1000 {
				break
			}
		}
	}
	return out
}

func parseSuricataRuleLine(meta, prefix string) map[string]interface{} {
	sid := extractRuleAttribute(meta, `sid:([0-9]+)`)
	if sid == "" {
		return nil
	}
	msg := firstNonEmpty(extractRuleAttribute(meta, `msg:"([^"]+)"`), prefix+" rule "+sid)
	field := suricataField(meta)
	value, operator := suricataPattern(meta)
	if value == "" {
		return nil
	}
	return map[string]interface{}{"id": prefix + "-" + sid, "name": msg, "category": "traffic", "severity": severityFromSuricataMessage(msg), "stage_hint": inferRuleStage("traffic", msg+" "+value), "field": field, "operator": operator, "value": value, "regex": operator == "regex", "source_operator": "suricata", "candidate": true}
}

func suricataField(meta string) string {
	switch {
	case strings.Contains(meta, "dns.query"):
		return "dns_query"
	case strings.Contains(meta, "tls.sni"):
		return "tls_sni"
	case strings.Contains(meta, "http.host"):
		return "http_host"
	case strings.Contains(meta, "http.uri") || strings.Contains(meta, "http.url"):
		return "http_path"
	default:
		return "payload"
	}
}

func suricataPattern(meta string) (string, string) {
	if p := extractRuleAttribute(meta, `pcre:"/([^"/]+)/[A-Za-z]*"`); p != "" {
		return p, "regex"
	}
	if p := extractRuleAttribute(meta, `content:"([^"]+)"`); p != "" {
		return decodeSuricataContent(p), "contains"
	}
	return "", ""
}

func decodeSuricataContent(content string) string {
	replacements := map[string]string{"|20": " ", "|2f": "/", "|2F": "/", "|3a": ":", "|3A": ":", "|2e": ".", "|2E": "."}
	for old, newValue := range replacements {
		content = strings.ReplaceAll(content, old, newValue)
	}
	return strings.TrimSpace(content)
}

func severityFromSuricataMessage(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "trojan") || strings.Contains(lower, "malware") || strings.Contains(lower, "exploit"):
		return "high"
	case strings.Contains(lower, "scan") || strings.Contains(lower, "policy") || strings.Contains(lower, "info"):
		return "low"
	default:
		return "medium"
	}
}

func stringSliceFromInterface(v interface{}) []string {
	items, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := asString(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func loadLocalCompiledRuleCorpus() []map[string]interface{} {
	paths := []string{"rules/compiled/live", "rules/compiled/scored-preview"}
	out := []map[string]interface{}{}
	seen := map[string]struct{}{}
	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var raw map[string]interface{}
			if json.Unmarshal(data, &raw) != nil {
				continue
			}
			id := asString(raw["id"])
			if id == "" {
				id = strings.TrimSuffix(entry.Name(), ".json")
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			rule := localCompiledRuleToRaw(raw)
			rule["snapshot_path"] = path
			out = append(out, rule)
		}
	}
	return out
}

func localCompiledRuleToRaw(raw map[string]interface{}) map[string]interface{} {
	category := normalizeLocalCompiledCategory(asString(raw["category"]), raw)
	match := mapValue(raw["match"])
	conditions := mapSlice(match["conditions"])
	convertedConditions := make([]map[string]interface{}, 0, len(conditions)+1)
	for _, condition := range conditions {
		field := mapLocalCompiledField(asString(condition["field"]), category)
		operator := strings.ToLower(firstNonEmpty(asString(condition["operator"]), "contains"))
		value := asString(condition["value"])
		if operator == "contains" && looksLikeRegexAlternation(value) {
			operator = "regex"
		}
		convertedConditions = append(convertedConditions, map[string]interface{}{"field": field, "operator": operator, "value": value, "regex": operator == "regex"})
	}
	if category == "traffic" {
		if content := suricataContentForTelemetry(match); content != "" {
			convertedConditions = append(convertedConditions, map[string]interface{}{"field": "payload", "operator": "contains", "value": content})
		}
	}
	scoring := mapValue(raw["scoring"])
	classification := mapValue(raw["classification"])
	if len(convertedConditions) == 0 {
		convertedConditions = append(convertedConditions, map[string]interface{}{"field": defaultRuleField(category), "operator": "contains", "value": asString(raw["name"])})
	}
	return map[string]interface{}{"id": asString(raw["id"]), "name": asString(raw["name"]), "category": category, "severity": firstNonEmpty(asString(scoring["severity"]), "medium"), "score_hint": firstNonZero(asInt(scoring["normalized_score"]), firstNonZero(asInt(scoring["base_score"]), 50)), "stage_hint": firstNonEmpty(asString(classification["stage"]), inferRuleStage(category, asString(raw["name"]))), "field": defaultRuleField(category), "operator": "contains", "value": asString(raw["name"]), "conditions": convertedConditions, "candidate": true, "source_operator": "compiled_v1", "upstream_id": asString(raw["id"]), "support_notes": []string{"imported from compiled v1 corpus"}}
}

func normalizeLocalCompiledCategory(category string, raw map[string]interface{}) string {
	switch strings.ToLower(category) {
	case "dpi", "traffic":
		return "traffic"
	case "hids":
		name := strings.ToLower(asString(raw["name"]) + " " + asString(raw["description"]))
		if strings.Contains(name, "process") || strings.Contains(name, "进程") || strings.Contains(name, "exec") || strings.Contains(name, "command") || strings.Contains(name, "命令") {
			return "runtime"
		}
		return "log_audit"
	case "runtime", "rasp", "log_audit":
		return category
	default:
		return normalizeComponentCategory(category)
	}
}

func mapLocalCompiledField(field, category string) string {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "metadata.line", "metadata.log_line", "message", "log.message":
		return "message"
	case "process.command_line", "process.cmdline", "cmdline":
		return "cmdline"
	case "network.protocol", "protocol":
		return "protocol"
	case "network.src_ip", "source.ip":
		return "source_ip"
	case "network.dst_ip", "destination.ip":
		return "target_ip"
	case "url.path", "http.path", "http_path":
		return "http_path"
	case "dns.question.name", "dns_query":
		return "dns_query"
	default:
		if field == "" {
			return defaultRuleField(category)
		}
		return strings.ReplaceAll(field, ".", "_")
	}
}

func looksLikeRegexAlternation(value string) bool {
	return strings.Contains(value, "|") || strings.Contains(value, "^") || strings.Contains(value, ".*")
}

func suricataContentForTelemetry(match map[string]interface{}) string {
	suricata := mapValue(match["suricata"])
	raw := asString(suricata["raw"])
	if raw == "" {
		return ""
	}
	re := regexp.MustCompile(`content:"([^"]+)"`)
	m := re.FindStringSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	content := strings.ReplaceAll(m[1], "|20", " ")
	content = strings.ReplaceAll(content, "|2f", "/")
	content = strings.ReplaceAll(content, "|3a", ":")
	content = strings.TrimSpace(content)
	if strings.Contains(content, "|") || len(content) < 3 {
		return ""
	}
	return content
}

func convertRulePlatformRules(source map[string]interface{}, version string, rawRules []map[string]interface{}) ([]map[string]interface{}, ruleSyncReport) {
	report := ruleSyncReport{SupportCounts: map[string]int{"full_supported": 0, "partial_supported": 0, "unsupported": 0}}
	converted := make([]map[string]interface{}, 0, len(rawRules))
	seen := map[string]string{}
	for _, raw := range rawRules {
		rule := normalizeRulePlatformRule(source, version, raw)
		support, notes := classifyRulePlatformSupport(rule)
		rule["support_level"] = support
		if len(notes) > 0 {
			rule["support_notes"] = notes
		}
		dedup := rulePlatformDedupKey(rule)
		rule["dedup_key"] = dedup
		report.SupportCounts[support]++
		if support == "unsupported" {
			report.Unsupported++
		}
		if previous, ok := seen[dedup]; ok {
			report.Duplicates++
			report.DedupGroups = append(report.DedupGroups, map[string]interface{}{"dedup_key": dedup, "winner": previous, "duplicate": rule["id"]})
			continue
		}
		seen[dedup] = asString(rule["id"])
		converted = append(converted, rule)
		report.Converted++
	}
	return converted, report
}

func normalizeRulePlatformRule(source map[string]interface{}, version string, raw map[string]interface{}) map[string]interface{} {
	category := normalizeComponentCategory(firstNonEmpty(asString(raw["category"]), asString(source["category"])))
	if category == "" || category == "all" {
		category = "rasp"
	}
	operator := strings.ToLower(firstNonEmpty(asString(raw["operator"]), asString(raw["source_operator"]), "contains"))
	field := firstNonEmpty(asString(raw["field"]), defaultRuleField(category))
	severity := firstNonEmpty(asString(raw["severity"]), "medium")
	ruleID := slugifyRulePlatformID(firstNonEmpty(asString(raw["id"]), asString(raw["name"]), asString(source["id"])+"-rule"))
	return map[string]interface{}{"id": ruleID, "name": firstNonEmpty(asString(raw["name"]), ruleID), "category": category, "severity": severity, "score_hint": firstNonZero(asInt(raw["score_hint"]), int(severityBaseScore(severity))), "stage_hint": firstNonEmpty(asString(raw["stage_hint"]), inferRuleStage(category, asString(raw["name"])+" "+asString(raw["value"]))), "field": field, "operator": operator, "value": asString(raw["value"]), "regex": operator == "regex" || operator == "pcre", "candidate": asBoolDefault(raw["candidate"], true), "source_id": asString(source["id"]), "source_version": version, "source_license": asString(source["license"]), "source_url": asString(source["url"]), "upstream_id": firstNonEmpty(asString(raw["upstream_id"]), asString(raw["id"])), "conditions": mapSlice(raw["conditions"]), "window": mapValue(raw["window"]), "group_by": asString(raw["group_by"])}
}

func classifyRulePlatformSupport(rule map[string]interface{}) (string, []string) {
	operator := strings.ToLower(asString(rule["operator"]))
	supported := map[string]bool{"contains": true, "regex": true, "pcre": true, "equals": true, "eq": true, "prefix": true, "suffix": true, "exists": true, "not_equals": true, "neq": true, "not_exists": true}
	conditions := mapSlice(rule["conditions"])
	if !supported[operator] {
		return "unsupported", []string{"unsupported_operator:" + operator}
	}
	if strings.TrimSpace(asString(rule["field"])) == "" {
		return "unsupported", []string{"missing_field"}
	}
	if operator != "exists" && operator != "not_exists" && strings.TrimSpace(asString(rule["value"])) == "" && len(conditions) == 0 {
		return "unsupported", []string{"missing_value"}
	}
	if operator == "regex" || operator == "pcre" || asBool(rule["regex"]) {
		if _, err := regexp.Compile(asString(rule["value"])); err != nil && strings.TrimSpace(asString(rule["value"])) != "" {
			return "unsupported", []string{"invalid_regex:" + err.Error()}
		}
	}
	for _, condition := range conditions {
		conditionOperator := strings.ToLower(firstNonEmpty(asString(condition["operator"]), "contains"))
		if !supported[conditionOperator] {
			return "unsupported", []string{"unsupported_condition_operator:" + conditionOperator}
		}
		if strings.TrimSpace(asString(condition["field"])) == "" {
			return "unsupported", []string{"missing_condition_field"}
		}
		if conditionOperator != "exists" && conditionOperator != "not_exists" && strings.TrimSpace(asString(condition["value"])) == "" {
			return "unsupported", []string{"missing_condition_value"}
		}
		if conditionOperator == "regex" || conditionOperator == "pcre" || asBool(condition["regex"]) {
			if _, err := regexp.Compile(asString(condition["value"])); err != nil {
				return "unsupported", []string{"invalid_condition_regex:" + err.Error()}
			}
		}
	}
	if operator == "pcre" {
		rule["operator"] = "regex"
		return "partial_supported", []string{"pcre_normalized_to_regex"}
	}
	if len(mapValue(rule["window"])) > 0 {
		return "partial_supported", []string{"window_metadata_preserved_without_stateful_threshold"}
	}
	return "full_supported", nil
}

func upsertConvertedDetectionRules(ctx context.Context, cfg *Config, sourceID string, rules []map[string]interface{}) (int, int, int, error) {
	inserted, duplicates, unsupported := 0, 0, 0
	for _, rule := range rules {
		support := asString(rule["support_level"])
		if support == "unsupported" {
			unsupported++
		}
		dedup := asString(rule["dedup_key"])
		id := sourceID + "-" + asString(rule["id"])
		var existing string
		err := cfg.DBPool.QueryRow(ctx, `SELECT id FROM detection_rules WHERE dedup_key=$1 LIMIT 1`, dedup).Scan(&existing)
		if err == nil && existing != id {
			duplicates++
			continue
		}
		raw, err := json.Marshal(rule)
		if err != nil {
			return inserted, duplicates, unsupported, err
		}
		enabled := support != "unsupported"
		if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO detection_rules (id, source_id, category, name, support_level, enabled, rule_json, dedup_key, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT (id) DO UPDATE SET category=EXCLUDED.category, name=EXCLUDED.name, support_level=EXCLUDED.support_level, rule_json=EXCLUDED.rule_json, dedup_key=EXCLUDED.dedup_key, updated_at=NOW()`, id, sourceID, rule["category"], rule["name"], support, enabled, string(raw), dedup); err != nil {
			return inserted, duplicates, unsupported, err
		}
		inserted++
	}
	return inserted, duplicates, unsupported, nil
}

func rulePlatformDedupKey(rule map[string]interface{}) string {
	parts := []string{asString(rule["category"]), asString(rule["field"]), strings.ToLower(asString(rule["operator"])), strings.ToLower(strings.TrimSpace(asString(rule["value"]))), asString(rule["stage_hint"])}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func defaultRuleField(category string) string {
	switch category {
	case "traffic":
		return "http_path"
	case "runtime":
		return "cmdline"
	case "log_audit":
		return "message"
	default:
		return "query"
	}
}

func inferRuleStage(category, haystack string) string {
	haystack = strings.ToLower(haystack)
	switch {
	case strings.Contains(haystack, "reverse") || strings.Contains(haystack, "shell"):
		return "execution"
	case strings.Contains(haystack, "admin") || strings.Contains(haystack, "scan"):
		return "recon"
	case category == "log_audit" || strings.Contains(haystack, "login") || strings.Contains(haystack, "password"):
		return "initial_access"
	default:
		return "detection"
	}
}

func loadRulePlatformVersions(ctx context.Context, cfg *Config, sourceID string) ([]map[string]interface{}, error) {
	query := `SELECT source_id, version, content_hash, COALESCE(snapshot_path,''), sync_status, synced_at FROM rule_source_versions`
	args := []interface{}{}
	if sourceID != "" {
		query += ` WHERE source_id=$1`
		args = append(args, sourceID)
	}
	query += ` ORDER BY synced_at DESC LIMIT 100`
	rows, err := cfg.DBPool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var source, version, hash, path, status string
		var synced time.Time
		if err := rows.Scan(&source, &version, &hash, &path, &status, &synced); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{"source_id": source, "version": version, "content_hash": hash, "snapshot_path": path, "sync_status": status, "synced_at": synced.Format(time.RFC3339)})
	}
	return items, rows.Err()
}

func rollbackRulePlatformBundle(ctx context.Context, cfg *Config, requestedVersion string) (map[string]interface{}, error) {
	rows, err := loadRulePlatformBundles(ctx, cfg)
	if err != nil {
		return nil, err
	}
	active := ""
	candidates := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		version := asString(row["version"])
		if row["status"] == "active" {
			active = version
			continue
		}
		if requestedVersion == "" || requestedVersion == version {
			candidates = append(candidates, row)
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no rollback bundle available")
	}
	sort.Slice(candidates, func(i, j int) bool {
		return asString(candidates[i]["created_at"]) > asString(candidates[j]["created_at"])
	})
	target := candidates[0]
	version := asString(target["version"])
	path := asString(target["bundle_path"])
	if path == "" {
		return nil, fmt.Errorf("bundle %s has no path", version)
	}
	reloadStatus := reloadSecurityEngine(ctx, cfg, path)
	if reloadStatus["status"] != "ok" {
		_, _ = cfg.DBPool.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version, target, status, message) VALUES ($1,$2,$3,$4)`, version, "ly-security-engine", "rollback_failed", reloadStatus["message"])
		return nil, fmt.Errorf("reload rollback bundle failed: %v", reloadStatus["message"])
	}
	if _, err := cfg.DBPool.Exec(ctx, `UPDATE rule_bundles SET status='inactive' WHERE status='active'`); err != nil {
		return nil, err
	}
	if _, err := cfg.DBPool.Exec(ctx, `UPDATE rule_bundles SET status='active', activated_at=NOW() WHERE version=$1`, version); err != nil {
		return nil, err
	}
	_, _ = cfg.DBPool.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version, target, status, message) VALUES ($1,$2,$3,$4)`, version, "ly-security-engine", "rollback_ok", "rolled back from "+active)
	target["status"] = "active"
	target["rollback_from"] = active
	target["reload"] = reloadStatus
	return target, nil
}

func loadRulePlatformSource(ctx context.Context, cfg *Config, sourceID string) (map[string]interface{}, error) {
	var id, name, category, origin, license, url string
	var bundled, connector, restricted, updatable bool
	var updated time.Time
	err := cfg.DBPool.QueryRow(ctx, `SELECT id, name, category, origin, COALESCE(license,''), COALESCE(url,''), bundled, connector, restricted, updatable, updated_at FROM rule_sources WHERE id=$1`, sourceID).Scan(&id, &name, &category, &origin, &license, &url, &bundled, &connector, &restricted, &updatable, &updated)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"id": id, "name": name, "category": category, "origin": origin, "license": license, "url": url, "bundled": bundled, "connector": connector, "restricted": restricted, "updatable": updatable, "updated_at": updated.Format(time.RFC3339)}, nil
}

func isRestrictedRuleLicense(license string) bool {
	license = strings.ToLower(strings.TrimSpace(license))
	return strings.Contains(license, "gpl") || strings.Contains(license, "agpl") || strings.Contains(license, "commercial") || strings.Contains(license, "proprietary") || strings.Contains(license, "restricted")
}
