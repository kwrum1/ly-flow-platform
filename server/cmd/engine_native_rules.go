package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

func nativeEngineRulesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		if limit <= 0 || limit > 200 {
			limit = 50
		}
		if offset < 0 {
			offset = 0
		}
		engineFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("engine")))
		query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
		items := loadNativeEngineRules(cfg)
		items = mergeDetectionRules(r.Context(), cfg, items)
		overrides := loadRuleOverrides()
		counts := map[string]int{"suricata": 0, "wazuh": 0, "yara": 0, "rasp": 0, "lyprobe": 0}
		filtered := make([]map[string]interface{}, 0, len(items))
		for _, item := range items {
			applyNativeRuleOverride(item, overrides)
			engine := asString(item["engine"])
			counts[engine]++
			if engineFilter != "" && engine != engineFilter {
				continue
			}
			if query != "" {
				data, _ := json.Marshal(item)
				if !strings.Contains(strings.ToLower(string(data)), query) {
					continue
				}
			}
			filtered = append(filtered, item)
		}
		listedCounts := maps.Clone(counts)
		root := firstNonEmpty(os.Getenv("ENGINE_RULE_ROOT"), "rules")
		trafficCount, err := activeLifecycleTrafficCount(r.Context(), cfg.RuleLifecycle, counts["suricata"], countRuleFiles(filepath.Join(root, "suricata")))
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_count_unverified", err.Error())
			return
		}
		counts["suricata"] = trafficCount.SignatureCount
		total := len(filtered)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": filtered[offset:end], "total": total, "limit": limit, "offset": offset, "counts": counts, "listed_counts": listedCounts, "count_semantics": map[string]interface{}{"suricata": trafficCount}}})
	}
}

func nativeEngineRulesUpdateHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		items := loadNativeEngineRules(cfg)
		counts := map[string]int{"suricata": 0, "wazuh": 0, "yara": 0, "rasp": 0, "lyprobe": 0}
		for _, item := range items {
			counts[asString(item["engine"])]++
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"status": "refreshed", "updated_at": time.Now().UTC().Format(time.RFC3339), "counts": counts, "total": len(items)}})
	}
}

func nativeEngineStatusHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		healthURL := firstNonEmpty(os.Getenv("SECURITY_ENGINE_HEALTH_URL"), "http://ly-security-engine:8080/health")
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, healthURL, nil)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "engine_health_unavailable", err.Error())
			return
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "engine_health_unavailable", err.Error())
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			writeJSONError(w, http.StatusServiceUnavailable, "engine_health_unavailable", response.Status)
			return
		}
		var health map[string]interface{}
		if err := json.NewDecoder(response.Body).Decode(&health); err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "engine_health_invalid", err.Error())
			return
		}
		status := map[string]interface{}{"source": "ly-security-engine", "engines": map[string]interface{}{"security-engine": health}}
		trafficCount, err := activeLifecycleTrafficCount(r.Context(), cfg.RuleLifecycle, 0, countRuleFiles("rules/suricata"))
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_count_unverified", err.Error())
			return
		}
		engines, ok := status["engines"].(map[string]interface{})
		if !ok {
			engines = map[string]interface{}{}
			status["engines"] = engines
		}
		trafficRuntime, ok := engines["suricata"].(map[string]interface{})
		if !ok {
			trafficRuntime = map[string]interface{}{}
			engines["suricata"] = trafficRuntime
		}
		trafficRuntime["signature_count"] = trafficCount.SignatureCount
		trafficRuntime["rule_file_count"] = trafficCount.RuleFileCount
		trafficRuntime["count_source"] = trafficCount.Source
		trafficRuntime["ledger_digest"] = trafficCount.LedgerDigest
		ruleRoot := firstNonEmpty(os.Getenv("ENGINE_RULE_ROOT"), "rules")
		lyprobeRules := loadLyprobeRules(filepath.Join(ruleRoot, "lyprobe", "threat.json"))
		lyprobeRuntime := map[string]interface{}{
			"installed":         len(lyprobeRules) > 0,
			"running":           false,
			"status":            "rules_loaded",
			"probe":             "lyprobe",
			"transport":         "netflow-v9",
			"rule_count":        len(lyprobeRules),
			"rule_pack_version": lyprobeManifestVersion(filepath.Join(ruleRoot, "lyprobe", "manifest.json")),
			"count_source":      filepath.Join(ruleRoot, "lyprobe", "threat.json"),
			"note":              "ET Open 子集由 rulecompiler 生成；NetFlow v9 证据链",
		}
		if lastExport, ok := lyprobeRecentFlowAt(r.Context(), cfg, time.Now()); ok {
			lyprobeRuntime["running"] = true
			lyprobeRuntime["status"] = "running"
			lyprobeRuntime["last_export"] = lastExport.UTC().Format(time.RFC3339)
		}
		engines["lyprobe"] = lyprobeRuntime
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": status})
	}
}

const lyprobeHeartbeatWindow = 5 * time.Minute

// lyprobeRecentFlowAt reports whether the raw flow stream has carried a
// lyprobe-sourced record recently. NetFlow v9 records arrive with
// source=lyprobe, so a fresh record is a real liveness signal even when the
// probe has no control-plane heartbeat channel.
func lyprobeRecentFlowAt(ctx context.Context, cfg *Config, now time.Time) (time.Time, bool) {
	if cfg == nil || cfg.Redis == nil {
		return time.Time{}, false
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	msgs, err := cfg.Redis.XRevRangeN(readCtx, "flows:raw", "+", "-", 5000).Result()
	if err != nil {
		return time.Time{}, false
	}
	return lyprobeRecentFlowFromMessages(msgs, now, lyprobeHeartbeatWindow)
}

func lyprobeRecentFlowFromMessages(msgs []redis.XMessage, now time.Time, window time.Duration) (time.Time, bool) {
	for _, msg := range msgs {
		payload := map[string]interface{}{}
		if raw := streamDataString(msg.Values); raw != "" {
			_ = json.Unmarshal([]byte(raw), &payload)
		}
		if len(payload) == 0 {
			for key, value := range msg.Values {
				payload[key] = value
			}
		}
		source := strings.ToLower(strings.TrimSpace(xdrPickString(payload, "source")))
		captureSource := strings.ToLower(strings.TrimSpace(xdrPickString(payload, "capture_source")))
		probeName := strings.ToLower(strings.TrimSpace(xdrPickString(payload, "probe_name")))
		if source != "lyprobe" &&
			!strings.Contains(source, "local-mirror") &&
			captureSource != "mirror" &&
			!strings.Contains(probeName, "mirror") &&
			!strings.Contains(probeName, "镜像") {
			continue
		}
		at := parseEventTime(payload)
		if at.IsZero() {
			if millis, err := strconv.ParseInt(strings.Split(msg.ID, "-")[0], 10, 64); err == nil {
				at = time.UnixMilli(millis)
			}
		}
		if at.IsZero() || at.Before(now.Add(-window)) {
			continue
		}
		return at, true
	}
	return time.Time{}, false
}

var nativeRulesCache struct {
	sync.Mutex
	at    time.Time
	items []map[string]interface{}
}

func loadNativeEngineRules(cfg *Config) []map[string]interface{} {
	nativeRulesCache.Lock()
	defer nativeRulesCache.Unlock()
	if len(nativeRulesCache.items) > 0 && time.Since(nativeRulesCache.at) < 2*time.Minute {
		return append([]map[string]interface{}(nil), nativeRulesCache.items...)
	}
	items := scanNativeEngineRules(cfg)
	nativeRulesCache.items = items
	nativeRulesCache.at = time.Now()
	return append([]map[string]interface{}(nil), items...)
}

func scanNativeEngineRules(cfg *Config) []map[string]interface{} {
	root := firstNonEmpty(os.Getenv("ENGINE_RULE_ROOT"), "rules")
	items := []map[string]interface{}{}
	items = append(items, scanRuleFiles("suricata", filepath.Join(root, "suricata"), []string{".rules"}, parseSuricataRule)...)
	items = append(items, scanRuleFiles("wazuh", filepath.Join(root, "wazuh"), []string{".xml", ".yml", ".yaml"}, parseWazuhRule)...)
	items = append(items, scanRuleFiles("wazuh", filepath.Join("third_party", "security-engines", "wazuh", "ruleset"), []string{".xml", ".yml", ".yaml"}, parseWazuhRule)...)
	items = append(items, scanRuleFiles("yara", filepath.Join(root, "yara"), []string{".yar", ".yara"}, parseYARARule)...)
	items = append(items, scanRuleFiles("rasp", filepath.Join(root, "rasp"), []string{".json", ".yaml", ".yml", ".js"}, parseRASPRule)...)
	items = append(items, loadLyprobeRules(filepath.Join(root, "lyprobe", "threat.json"))...)
	if len(items) == 0 && root != "rules" {
		items = append(items, scanNativeEngineRules(&Config{})...)
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := asString(items[i]["engine"]) + asString(items[i]["path"]) + asString(items[i]["id"])
		right := asString(items[j]["engine"]) + asString(items[j]["path"]) + asString(items[j]["id"])
		return left < right
	})
	return items
}

func mergeDetectionRules(ctx context.Context, cfg *Config, items []map[string]interface{}) []map[string]interface{} {
	if cfg == nil || cfg.DBPool == nil {
		return items
	}
	rows, err := cfg.DBPool.Query(ctx, `SELECT id, COALESCE(source_id,''), category, name, support_level, enabled, rule_json::text FROM detection_rules WHERE category='traffic' ORDER BY source_id, id`)
	if err != nil {
		return items
	}
	defer rows.Close()
	seen := map[string]bool{}
	for _, item := range items {
		seen[asString(item["id"])] = true
	}
	for rows.Next() {
		var id, sourceID, category, name, support, raw string
		var enabled bool
		if err := rows.Scan(&id, &sourceID, &category, &name, &support, &enabled, &raw); err != nil {
			continue
		}
		if seen[id] {
			continue
		}
		var rule map[string]interface{}
		_ = json.Unmarshal([]byte(raw), &rule)
		severity := firstNonEmpty(asString(rule["severity"]), "medium")
		path := "compiled/traffic-feeds"
		if sourceID != "" {
			path = "compiled/traffic-feeds/" + sourceID
		}
		items = append(items, map[string]interface{}{"id": id, "name": name, "enabled": enabled, "severity": severity, "engine": "suricata", "path": path, "line": 0, "native_type": "traffic_feed_rule", "source_id": sourceID, "support_level": support})
	}
	return items
}

func nativeRuleOverrideID(item map[string]interface{}) string {
	return strings.Join([]string{asString(item["engine"]), asString(item["path"]), asString(item["line"]), asString(item["id"])}, ":")
}

func applyNativeRuleOverride(item map[string]interface{}, overrides map[string]interface{}) {
	ids := []string{asString(item["id"]), nativeRuleOverrideID(item)}
	for _, id := range ids {
		current, ok := overrides[id].(map[string]interface{})
		if !ok {
			continue
		}
		for key, value := range current {
			item[key] = value
		}
	}
	if strings.EqualFold(asString(item["severity"]), "info") {
		item["enabled"] = false
	}
}

type nativeRuleParser func(path string, lineNo int, line string) (map[string]interface{}, bool)

func scanRuleFiles(engine, dir string, exts []string, parser nativeRuleParser) []map[string]interface{} {
	items := []map[string]interface{}{}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !hasExt(path, exts) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if item, ok := parser(path, i+1, strings.TrimSpace(line)); ok {
				item["engine"] = engine
				item["path"] = path
				item["line"] = i + 1
				items = append(items, item)
			}
		}
		return nil
	})
	return items
}

func hasExt(path string, exts []string) bool {
	lower := strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func parseSuricataRule(path string, lineNo int, line string) (map[string]interface{}, bool) {
	if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "sid:") {
		return nil, false
	}
	return map[string]interface{}{"id": between(line, "sid:", ";"), "name": between(line, "msg:\"", "\""), "enabled": true, "native_type": "suricata_rule"}, true
}

func parseWazuhRule(path string, lineNo int, line string) (map[string]interface{}, bool) {
	if strings.Contains(line, "<rule ") && strings.Contains(line, "id=\"") {
		return map[string]interface{}{"id": between(line, "id=\"", "\""), "name": firstNonEmpty(between(line, "description=\"", "\""), "Wazuh XML rule"), "enabled": true, "native_type": "wazuh_xml"}, true
	}
	if strings.HasPrefix(line, "id:") || strings.HasPrefix(line, "- id:") || strings.HasPrefix(line, "title:") || strings.HasPrefix(line, "name:") {
		value := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(line, "- id:"), "id:"), "title:"), "name:")), "\"'")
		if value != "" {
			return map[string]interface{}{"id": filepath.Base(path), "name": value, "enabled": true, "native_type": "wazuh_sca"}, true
		}
	}
	return nil, false
}

func parseYARARule(path string, lineNo int, line string) (map[string]interface{}, bool) {
	if !strings.HasPrefix(line, "rule ") && !strings.Contains(line, " rule ") {
		return nil, false
	}
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "private "), "global "))
	name = strings.TrimSpace(strings.TrimPrefix(name, "rule "))
	if idx := strings.IndexAny(name, " {:"); idx >= 0 {
		name = name[:idx]
	}
	if name == "" {
		return nil, false
	}
	return map[string]interface{}{"id": name, "name": name, "enabled": true, "native_type": "yara_rule"}, true
}

func parseRASPRule(path string, lineNo int, line string) (map[string]interface{}, bool) {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil, false
	}
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return map[string]interface{}{"id": base, "name": base, "enabled": true, "native_type": "rasp_plugin"}, true
}

func between(s, start, end string) string {
	idx := strings.Index(s, start)
	if idx < 0 {
		return ""
	}
	s = s[idx+len(start):]
	if end != "" {
		if j := strings.Index(s, end); j >= 0 {
			s = s[:j]
		}
	}
	return strings.TrimSpace(s)
}

// loadLyprobeRules exposes the generated ly_probe threat bundle to the rule
// inventory. The bundle is produced by server/cmd/rulecompiler from the
// conservative Suricata subset in rules/lyprobe/source, so this is a real
// installed rule set rather than a placeholder.
func loadLyprobeRules(path string) []map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var bundle struct {
		Threat struct {
			Rules map[string]map[string]interface{} `json:"rules"`
		} `json:"threat"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil
	}
	items := make([]map[string]interface{}, 0, len(bundle.Threat.Rules))
	for id, rule := range bundle.Threat.Rules {
		ruleType := strings.ToUpper(asString(rule["type"]))
		severity := "medium"
		switch ruleType {
		case "MALWARE", "TROJAN", "C2", "EXPLOIT":
			severity = "high"
		case "WEB", "SCAN":
			severity = "medium"
		}
		items = append(items, map[string]interface{}{
			"id":          id,
			"name":        firstNonEmpty(asString(rule["name"]), asString(rule["desc"]), id),
			"enabled":     true,
			"severity":    severity,
			"engine":      "lyprobe",
			"path":        path,
			"line":        0,
			"native_type": "lyprobe_threat",
			"source_id":   "et-open-lyprobe",
			"rule_type":   ruleType,
			"protocol":    asString(rule["protocol"]),
			"regex":       asString(rule["regex"]),
		})
	}
	return items
}

func lyprobeManifestVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "lyprobe-local"
	}
	var manifest struct {
		GeneratedAt string `json:"generated_at"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || strings.TrimSpace(manifest.GeneratedAt) == "" {
		return "lyprobe-local"
	}
	return manifest.GeneratedAt
}
