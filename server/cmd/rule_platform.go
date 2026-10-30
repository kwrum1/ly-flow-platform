package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
)

const rulePlatformSyncBodyLimit int64 = 65 << 20

// rulePlatformParserVersion is bumped whenever the conversion quality rules
// change. It is mixed into the stored source digest so an unchanged upstream
// feed can never keep an active bundle produced by an older parser.
const rulePlatformParserVersion = "2026-10-30.9"

// retiredDefaultDetectionRuleIDs are bundled rules that produced more noise
// than signal. They are removed from the shipped bundle and are also disabled
// in older databases so an upgrade or re-sync cannot bring them back.
var retiredDefaultDetectionRuleIDs = []string{
	"dpi-admin-access-default",
	"log-collector-heartbeat-default",
}

func retiredDefaultRuleID(id string) bool {
	trimmed := strings.TrimSpace(id)
	for _, retired := range retiredDefaultDetectionRuleIDs {
		if trimmed == retired {
			return true
		}
	}
	return false
}

// retiredConvertedRuleIDs are upstream conversions whose surviving pattern is
// only a common URL fragment. snort-community-51544 for example matches any
// request whose path contains "/upload_files", which fired on the benign asset
// /statics/admin/js/upload/upload_Files.js.
var retiredConvertedRuleIDs = []string{
	"snort-community-51542",
	"snort-community-51544",
	"snort-community-51546",
}

func retiredDetectionRuleID(id string) bool {
	if retiredDefaultRuleID(id) {
		return true
	}
	trimmed := strings.TrimSpace(id)
	for _, retired := range retiredConvertedRuleIDs {
		if trimmed == retired {
			return true
		}
	}
	return false
}

// convertedTrafficSourcePrefixes are external signature feeds that this server
// flattens into a single field/pattern rule. That flattening drops companion
// Suricata options (flow, dsize, offset, depth, threshold, urilen, ...), so a
// low-specificity pattern becomes a catch-all. Rules from these sources are
// only allowed into the runtime bundle when the surviving pattern contains a
// distinctive literal.
var convertedTrafficSourcePrefixes = []string{
	"et-open-",
	"ptresearch-attackdetection-",
	"snort-community-",
	"stamus-lateral-",
	"oisf-trafficid-",
}

// convertedSourcePrefixes also covers rule families that are flattened into a
// condition list rather than a single signature: Sigma conversions lose the
// upstream AND/OR grouping, so they need the same specificity gate.
var convertedSourcePrefixes = append(append([]string{}, convertedTrafficSourcePrefixes...), "sigma-")

type ruleVersionStatusCommitter interface {
	MarkSynced(ctx context.Context, sourceID, version, digest string) error
}

func commitSyncedRuleBundle(ctx context.Context, cfg *Config, sourceID, sourceVersion, sourceDigest string, manifest rulelifecycle.ActiveManifest) error {
	tx, err := cfg.DBPool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin synced rule bundle transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `UPDATE rule_source_versions SET sync_status='synced', synced_at=NOW() WHERE source_id=$1 AND version=$2 AND content_hash=$3`, sourceID, sourceVersion, sourceDigest)
	if err != nil {
		return fmt.Errorf("mark rule version synced: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("mark rule version synced affected %d rows: %w", result.RowsAffected(), rulelifecycle.ErrRevision)
	}
	if _, err := tx.Exec(ctx, `UPDATE rule_bundles SET status='inactive' WHERE status='active'`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rule_bundles (version,status,bundle_hash,bundle_path,activated_at) VALUES ($1,'active',$2,$3,NOW()) ON CONFLICT (version) DO UPDATE SET status='active', bundle_hash=EXCLUDED.bundle_hash, bundle_path=EXCLUDED.bundle_path, activated_at=NOW()`, manifest.Revision, manifest.Digest, manifest.BundlePath); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version,target,status,message) VALUES ($1,$2,'ok',$3)`, manifest.Revision, "ly-security-engine", manifest.BundlePath); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func rulePlatformSourcesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if body, ok := rulePlatformSourcesResponseCache.get("rule-platform-sources"); ok {
				_, _ = w.Write(body)
				return
			}
			items, err := loadRulePlatformSources(r.Context(), cfg)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "rule_sources_failed", err.Error())
				return
			}
			body, err := json.Marshal(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{
				"items": items, "total": len(items),
				"freshness": rulePlatformFreshness(r.Context(), cfg),
			}})
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "rule_sources_encode_failed", err.Error())
				return
			}
			rulePlatformSourcesResponseCache.set("rule-platform-sources", body)
			_, _ = w.Write(body)
		case http.MethodPost:
			var req map[string]interface{}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				var sizeErr *http.MaxBytesError
				if errors.As(err, &sizeErr) {
					writeJSONError(w, http.StatusRequestEntityTooLarge, "source_body_too_large", "Request body exceeds 1 MiB")
					return
				}
				writeJSONError(w, http.StatusBadRequest, "invalid_source", "Invalid request body")
				return
			}
			row, err := upsertRulePlatformSource(r.Context(), cfg, req)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "source_save_failed", err.Error())
				return
			}
			rulePlatformSourcesResponseCache.clear()
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
		if r.Method == http.MethodGet {
			// Status endpoint for the async "sync all" job; same route so the
			// route contract does not change.
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": rulePlatformSyncStatus()})
			return
		}
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, rulePlatformSyncBodyLimit)).Decode(&req); err != nil {
			var sizeErr *http.MaxBytesError
			if errors.As(err, &sizeErr) {
				writeJSONError(w, http.StatusRequestEntityTooLarge, "sync_body_too_large", "Request body exceeds 65 MiB")
				return
			}
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
		preview, err := stageSecurityBundlePreview(r.Context(), cfg)
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
	rows, err := cfg.DBPool.Query(ctx, `
		SELECT rs.id, rs.name, rs.category, rs.origin, COALESCE(rs.license,''), COALESCE(rs.url,''),
		       rs.bundled, rs.connector, rs.restricted, rs.updatable, rs.updated_at,
		       COALESCE(v.version,''), COALESCE(v.content_hash,''), COALESCE(v.sync_status,''), v.synced_at
		FROM rule_sources rs
		LEFT JOIN LATERAL (
			SELECT version, content_hash, sync_status, synced_at
			FROM rule_source_versions
			WHERE source_id = rs.id
			ORDER BY synced_at DESC
			LIMIT 1
		) v ON true
		ORDER BY rs.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, category, origin, license, url string
		var bundled, connector, restricted, updatable bool
		var updated time.Time
		var version, contentHash, syncStatus string
		var syncedAt *time.Time
		if err := rows.Scan(&id, &name, &category, &origin, &license, &url,
			&bundled, &connector, &restricted, &updatable, &updated,
			&version, &contentHash, &syncStatus, &syncedAt); err != nil {
			return nil, err
		}
		if restricted && !cfg.RuleDownloadRestrictedShown {
			continue
		}
		entry := map[string]interface{}{
			"id": id, "source_id": id, "name": name, "category": category, "origin": origin,
			"license": license, "url": url, "bundled": bundled, "connector": connector,
			"restricted": restricted, "updatable": updatable, "updated_at": updated.Format(time.RFC3339),
			"current_version": version, "content_hash": contentHash, "sync_status": syncStatus,
			"version_known": version != "",
		}
		if syncedAt != nil {
			entry["last_sync_at"] = syncedAt.UTC().Format(time.RFC3339)
		}
		if contentHash != "" {
			short := contentHash
			if len(short) > 12 {
				short = short[:12]
			}
			entry["display_version"] = "sha256-" + short
		}
		items = append(items, entry)
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
	if id == "" {
		id = slugifyRulePlatformID(name)
	}
	if cfg.RuleLifecycle == nil {
		return nil, errors.New("secure rule lifecycle is unavailable")
	}
	actor := ruleLifecycleActor(ctx)
	if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.upsert.attempt", id, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"has_url": url != ""}); err != nil {
		return nil, err
	}
	if url != "" {
		if err := cfg.RuleLifecycle.ValidateSourceURL(ctx, url); err != nil {
			if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.upsert", id, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
				return nil, auditErr
			}
			return nil, err
		}
	}
	bundled := asBool(req["bundled"])
	connector := asBool(req["connector"])
	restricted := asBool(req["restricted"])
	updatable := asBool(req["updatable"])
	_, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_sources (id, name, category, origin, license, url, bundled, connector, restricted, updatable, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW()) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, category=EXCLUDED.category, origin=EXCLUDED.origin, license=EXCLUDED.license, url=EXCLUDED.url, bundled=EXCLUDED.bundled, connector=EXCLUDED.connector, restricted=EXCLUDED.restricted, updatable=EXCLUDED.updatable, updated_at=NOW()`, id, name, category, origin, license, url, bundled, connector, restricted, updatable)
	if err != nil {
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.upsert", id, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.upsert", id, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"has_url": url != ""}); err != nil {
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

func stageSecurityBundlePreview(ctx context.Context, cfg *Config) (map[string]interface{}, error) {
	if cfg.RuleLifecycle == nil {
		return nil, errors.New("secure rule lifecycle is unavailable")
	}
	if err := ensureDefaultDetectionRules(ctx, cfg); err != nil {
		return nil, err
	}
	rules, err := loadEnabledDetectionRules(ctx, cfg)
	if err != nil {
		return nil, err
	}
	version := "preview-" + time.Now().UTC().Format("20060102150405.000000000")
	data, err := json.Marshal(compiledBundleFile{Version: version, Rules: rules})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	preview, err := cfg.RuleLifecycle.StageLocal(ctx, ruleLifecycleActor(ctx), rulelifecycle.LocalSource{
		SourceID: "database-detection-rules", Revision: version, SHA256: hex.EncodeToString(digest[:]), Content: data,
	})
	if err != nil {
		return nil, err
	}
	counts := map[string]int{"traffic": 0, "runtime": 0, "rasp": 0, "log_audit": 0}
	for _, rule := range rules {
		counts[rule.Category]++
	}
	return map[string]interface{}{"version": preview.Revision, "bundle_hash": preview.Digest, "rule_count": preview.RuleCount, "rule_counts": counts, "would_activate": preview.WouldActivate}, nil
}

func compileDefaultSecurityBundle(ctx context.Context, cfg *Config) (map[string]interface{}, error) {
	if cfg.RuleLifecycle == nil {
		return nil, errors.New("secure rule lifecycle is unavailable")
	}
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
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	actor := ruleLifecycleActor(ctx)
	preview, err := cfg.RuleLifecycle.StageLocal(ctx, actor, rulelifecycle.LocalSource{
		SourceID: "database-detection-rules", Revision: version, SHA256: hash, Content: data,
	})
	if err != nil {
		return nil, err
	}
	manifest, err := (ruleBundleActivation{config: cfg, actor: actor, version: version, digest: hash}).activate(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"version": version, "status": "active", "bundle_hash": hash, "bundle_path": manifest.BundlePath, "manifest_signature": manifest.Signature, "activated_at": manifest.ActivatedAt.Format(time.RFC3339), "rule_count": preview.RuleCount, "reload": map[string]interface{}{"status": "ok", "message": manifest.BundlePath}}, nil
}

func ensureDefaultDetectionRules(ctx context.Context, cfg *Config) error {
	bundlePath := getEnv("RULE_DEFAULT_BUNDLE", "rules/security-engine/default-bundle.json")
	data, err := os.ReadFile(bundlePath)
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
	// Retire rules that shipped in older bundles. Keeping this in the startup
	// path means a reinstall or re-sync cannot re-enable them on an existing DB.
	for _, retired := range retiredDefaultDetectionRuleIDs {
		if _, err := cfg.DBPool.Exec(ctx, `UPDATE detection_rules SET enabled=false, support_level='unsupported', updated_at=NOW() WHERE id=$1`, retired); err != nil {
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
	skippedGeneric := 0
	for rows.Next() {
		var id, category, name, support, raw string
		if err := rows.Scan(&id, &category, &name, &support, &raw); err != nil {
			return nil, err
		}
		if support == "unsupported" {
			continue
		}
		if retiredDetectionRuleID(id) {
			continue
		}
		rule, err := compileDetectionRule(id, category, name, raw)
		if err != nil {
			return nil, err
		}
		if !compiledRuntimeRuleValid(rule) {
			return nil, fmt.Errorf("rule %s failed strict runtime validation", id)
		}
		if compiledRuleIsOverBroad(rule) {
			skippedGeneric++
			continue
		}
		rules = append(rules, rule)
	}
	if skippedGeneric > 0 {
		log.Printf("[rule-platform] skipped %d over-broad converted traffic rules while building the active bundle", skippedGeneric)
	}
	return rules, rows.Err()
}

func loadEnabledDetectionRulesExcludingSource(ctx context.Context, cfg *Config, sourceID string) ([]compiledRuntimeRule, error) {
	rows, err := cfg.DBPool.Query(ctx, `SELECT id, category, name, support_level, rule_json::text FROM detection_rules WHERE enabled=true AND source_id<>$1 ORDER BY category, id`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []compiledRuntimeRule{}
	skippedGeneric := 0
	for rows.Next() {
		var id, category, name, support, raw string
		if err := rows.Scan(&id, &category, &name, &support, &raw); err != nil {
			return nil, err
		}
		if support == "unsupported" {
			continue
		}
		if retiredDetectionRuleID(id) {
			continue
		}
		rule, err := compileDetectionRule(id, category, name, raw)
		if err != nil {
			return nil, err
		}
		if !compiledRuntimeRuleValid(rule) {
			return nil, fmt.Errorf("rule %s failed strict runtime validation", id)
		}
		if compiledRuleIsOverBroad(rule) {
			skippedGeneric++
			continue
		}
		rules = append(rules, rule)
	}
	if skippedGeneric > 0 {
		log.Printf("[rule-platform] skipped %d over-broad converted traffic rules from other sources", skippedGeneric)
	}
	return rules, rows.Err()
}

// rulePlatformContentDigest binds the raw upstream digest to the parser
// version. A parser change therefore invalidates the incremental "unchanged"
// shortcut and forces a rebuild instead of keeping a stale, noisy bundle.
func rulePlatformContentDigest(rawDigest string) string {
	sum := sha256.Sum256([]byte("parser:" + rulePlatformParserVersion + "\x00" + rawDigest))
	return hex.EncodeToString(sum[:])
}

func convertedTrafficRuleID(id string) bool {
	lower := strings.ToLower(strings.TrimSpace(id))
	for _, prefix := range convertedTrafficSourcePrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

func longestAlnumRun(value string) int {
	longest, current := 0, 0
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			current++
			if current > longest {
				longest = current
			}
			continue
		}
		current = 0
	}
	return longest
}

// regexLiteralRun strips character classes and escapes before measuring the
// longest literal run. Without this, "\x2ejpg" would count as six literal
// characters even though it is just ".jpg".
func regexLiteralRun(value string) int {
	var builder strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '[' {
			i++
			for i < len(value) && value[i] != ']' {
				if value[i] == '\\' && i+1 < len(value) {
					i++
				}
				i++
			}
			continue
		}
		if ch == '\\' && i+1 < len(value) {
			next := value[i+1]
			if next == 'x' && i+3 < len(value) {
				i += 3
				continue
			}
			i++
			continue
		}
		builder.WriteByte(ch)
	}
	return longestAlnumRun(builder.String())
}

// rulePatternIsSpecific decides whether a flattened pattern is distinctive
// enough to run without the Suricata options that were dropped in conversion.
func rulePatternIsSpecific(value, operator string) bool {
	operator = strings.ToLower(strings.TrimSpace(operator))
	trimmed := strings.TrimSpace(value)
	if bareDomainPattern.MatchString(trimmed) {
		return false
	}
	if commonConvertedTokens[strings.ToLower(trimmed)] {
		return false
	}
	if operator == "regex" || operator == "pcre" {
		if strings.Contains(value, ")?") {
			return false // the only literal may be optional
		}
		return regexLiteralRun(value) >= 6
	}
	return longestAlnumRun(value) >= 6
}

var bareDomainPattern = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9.-]*\.(com|net|org|cn|io|ru|info|biz|xyz|top|cc|me|tv|co|uk|de|jp|fr|edu|gov|cloud|online|site|app|dev)$`)

var commonConvertedTokens = map[string]bool{
	"server": true, "windows": true, "microsoft": true, "samba": true,
	"password": true, "admin": true, "login": true, "http": true,
	"https": true, "user": true, "root": true, "shell": true,
	"select": true, "union": true, "system": true, "network": true,
	"client": true, "update": true, "service": true, "security": true,
	"google": true, "facebook": true, "debian": true, "ubuntu": true,
}

// convertedTrafficRuleRejection explains why a flattened external signature
// must not enter the flow engine. The runtime keeps only one field/pattern and
// cannot enforce the port, direction or offset constraints of the original, so
// a weak pattern turns into a catch-all and a binary pattern becomes dead.
func convertedTrafficRuleRejection(rule map[string]interface{}, operator string) string {
	value := strings.TrimSpace(asString(rule["value"]))
	if operator == "contains" && strings.Contains(value, "|") {
		return "unrepresentable_binary_content"
	}
	if bareDomainPattern.MatchString(value) {
		return "bare_domain"
	}
	if commonConvertedTokens[strings.ToLower(value)] {
		return "common_token"
	}
	run := longestAlnumRun(value)
	if operator == "regex" || operator == "pcre" {
		run = regexLiteralRun(value)
	}
	if run < 6 {
		return "pattern_too_generic"
	}
	port := strings.TrimSpace(asString(rule["source_dest_port"]))
	flow := strings.ToLower(asString(rule["source_flow"]))
	lost := false
	if port != "" && !strings.EqualFold(port, "any") && port != "$HTTP_PORTS" && port != "$SSH_PORTS" {
		lost = true
	}
	if strings.Contains(flow, "from_server") || strings.Contains(flow, "to_client") {
		lost = true
	}
	if len(stringSliceValue(rule["source_match_options"])) > 0 {
		lost = true
	}
	if lost && run < 12 {
		return "lost_match_constraints"
	}
	return ""
}

func stringSliceValue(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if trimmed := strings.TrimSpace(asString(item)); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	}
	return nil
}

func compiledRuleIsOverBroad(rule compiledRuntimeRule) bool {
	if !convertedRuleID(rule.ID) {
		return false
	}
	if compiledTrafficRuleIsGeneric(rule) {
		return true
	}
	if len(rule.Conditions) == 0 {
		if strings.EqualFold(strings.TrimSpace(rule.Category), "traffic") {
			return false
		}
		return !rulePatternIsSpecific(rule.Value, rule.Operator)
	}
	specific := false
	for _, condition := range rule.Conditions {
		if sigmaConditionHasWeakAlternation(condition) {
			return true
		}
		field := strings.TrimSpace(asString(condition["field"]))
		value := strings.TrimSpace(asString(condition["value"]))
		if field == "" || value == "" {
			return true
		}
		if sigmaConditionValueIsSpecific(field, value) {
			specific = true
		}
	}
	return !specific
}

func convertedRuleID(id string) bool {
	lower := strings.ToLower(strings.TrimSpace(id))
	for _, prefix := range convertedSourcePrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

func compiledTrafficRuleIsGeneric(rule compiledRuntimeRule) bool {
	if !strings.EqualFold(strings.TrimSpace(rule.Category), "traffic") {
		return false
	}
	if !convertedTrafficRuleID(rule.ID) {
		return false
	}
	if len(rule.Conditions) > 0 {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(rule.Operator), "contains") && strings.Contains(rule.Value, "|") {
		return true
	}
	return !rulePatternIsSpecific(rule.Value, rule.Operator)
}

func mergeCompiledRuntimeRules(base, updates []compiledRuntimeRule) []compiledRuntimeRule {
	byID := make(map[string]compiledRuntimeRule, len(base)+len(updates))
	for _, rule := range base {
		if retiredDetectionRuleID(rule.ID) || compiledRuleIsOverBroad(rule) {
			continue
		}
		byID[rule.ID] = rule
	}
	// Freshly converted rules take the same gate as database rules; otherwise a
	// sync reintroduces exactly the catch-alls the gate was added to stop.
	for _, rule := range updates {
		if retiredDetectionRuleID(rule.ID) || compiledRuleIsOverBroad(rule) {
			delete(byID, rule.ID)
			continue
		}
		byID[rule.ID] = rule
	}
	merged := make([]compiledRuntimeRule, 0, len(byID))
	for _, rule := range byID {
		merged = append(merged, rule)
	}
	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Category == merged[j].Category {
			return merged[i].ID < merged[j].ID
		}
		return merged[i].Category < merged[j].Category
	})
	return merged
}

func loadActiveLifecycleRules(ctx context.Context, cfg *Config) ([]compiledRuntimeRule, error) {
	if cfg.RuleLifecycle == nil {
		return nil, errors.New("secure rule lifecycle is unavailable")
	}
	manifest, err := cfg.RuleLifecycle.Active(ctx)
	if err != nil {
		return nil, err
	}
	var bundle compiledBundleFile
	if err := readJSONFile(manifest.BundlePath, &bundle); err != nil {
		return nil, err
	}
	return bundle.Rules, nil
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

// ruleSyncJobState tracks the background "sync all" job. Fetching a dozen
// upstream feeds cannot happen inside one HTTP request: nginx times out and the
// operator sees a 502 with no idea what happened.
type ruleSyncJobState struct {
	Running          bool                     `json:"running"`
	StartedAt        time.Time                `json:"started_at"`
	FinishedAt       *time.Time               `json:"finished_at,omitempty"`
	Version          string                   `json:"version"`
	Total            int                      `json:"total"`
	Applied          int                      `json:"applied"`
	Unchanged        int                      `json:"unchanged"`
	Failed           int                      `json:"failed"`
	Skipped          int                      `json:"skipped"`
	Current          string                   `json:"current_source,omitempty"`
	CurrentStartedAt time.Time                `json:"current_started_at,omitempty"`
	Results          []map[string]interface{} `json:"results"`
}

var ruleSyncJob = struct {
	mu    sync.Mutex
	state *ruleSyncJobState
}{}

// startRuleSyncScheduler keeps upstream rule sources fresh without an
// operator clicking "sync" every day. It is explicitly opt-out (0 hours) and
// runs the same audited job as the console button.
var ruleSyncSchedulerStarted atomic.Bool

func startRuleSyncScheduler(cfg *Config) {
	if !ruleSyncSchedulerStarted.CompareAndSwap(false, true) {
		return
	}
	hours := toInt(getEnv("LYFLOW_RULE_SYNC_INTERVAL_HOURS", "24"))
	if hours <= 0 {
		log.Printf("rule auto-sync disabled (LYFLOW_RULE_SYNC_INTERVAL_HOURS<=0)")
		return
	}
	interval := time.Duration(hours) * time.Hour
	log.Printf("rule auto-sync enabled: every %s", interval)
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			startRulePlatformSyncAll(cfg, 0, auth.RoleAdmin)
			timer.Reset(interval)
		}
	}
}

// rulePlatformFreshness reports how old the newest upstream sync is. A rule
// pack that has never been synced is "degraded", not "ok".
func rulePlatformFreshness(ctx context.Context, cfg *Config) componentStatus {
	intervalHours := toInt(getEnv("LYFLOW_RULE_SYNC_INTERVAL_HOURS", "24"))
	if intervalHours <= 0 {
		return componentStatus{Status: "ok", Message: "rule auto-sync disabled", Details: map[string]interface{}{"auto_sync": false}}
	}
	if cfg == nil || cfg.DBPool == nil {
		return componentStatus{Status: "error", Message: "database unavailable"}
	}
	var last *time.Time
	if err := cfg.DBPool.QueryRow(ctx, `SELECT max(synced_at) FROM rule_source_versions`).Scan(&last); err != nil {
		return componentStatus{Status: "unknown", Message: err.Error()}
	}
	if last == nil || last.IsZero() {
		return componentStatus{Status: "degraded", Message: "no rule source has ever been synced", Details: map[string]interface{}{"auto_sync": true, "interval_hours": intervalHours}}
	}
	age := time.Since(*last)
	details := map[string]interface{}{
		"auto_sync":      true,
		"interval_hours": intervalHours,
		"last_sync_at":   last.UTC().Format(time.RFC3339),
		"age_hours":      math.Round(age.Hours()*10) / 10,
		"stale_after":    last.Add(time.Duration(intervalHours) * 3 / 2 * time.Hour).UTC().Format(time.RFC3339),
	}
	if age > time.Duration(intervalHours)*3/2*time.Hour {
		return componentStatus{Status: "degraded", Message: "rule sources are older than the freshness budget", Details: details}
	}
	return componentStatus{Status: "ok", Message: "rule sources are fresh", Details: details}
}

// syncAllRulePlatformSources starts the background job and returns immediately.
// The caller's identity is carried into the job: the lifecycle audit rejects an
// anonymous actor, and a background goroutine has no request context.
func syncAllRulePlatformSources(ctx context.Context, cfg *Config, _ map[string]interface{}) (map[string]interface{}, error) {
	return startRulePlatformSyncAll(cfg, auth.GetUserIDFromContext(ctx), auth.GetRoleFromContext(ctx)), nil
}

func startRulePlatformSyncAll(cfg *Config, actorID int64, role auth.UserRole) map[string]interface{} {
	ruleSyncJob.mu.Lock()
	if ruleSyncJob.state != nil && ruleSyncJob.state.Running {
		view := ruleSyncJobViewLocked()
		ruleSyncJob.mu.Unlock()
		return view
	}
	state := &ruleSyncJobState{
		Running:   true,
		StartedAt: time.Now().UTC(),
		Version:   "sync-" + time.Now().UTC().Format("20060102T150405Z"),
		Results:   []map[string]interface{}{},
	}
	ruleSyncJob.state = state
	ruleSyncJob.mu.Unlock()

	go runRulePlatformSyncAll(cfg, state, actorID, role)

	return map[string]interface{}{
		"mode":       "async",
		"running":    true,
		"version":    state.Version,
		"started_at": state.StartedAt.Format(time.RFC3339),
	}
}

func ruleSyncJobViewLocked() map[string]interface{} {
	state := ruleSyncJob.state
	if state == nil {
		return map[string]interface{}{"mode": "async", "running": false}
	}
	completed := state.Applied + state.Unchanged + state.Failed
	progress := 0.0
	if state.Total > 0 {
		progress = float64(completed) / float64(state.Total) * 100
	}
	view := map[string]interface{}{
		"mode":             "async",
		"running":          state.Running,
		"version":          state.Version,
		"started_at":       state.StartedAt.Format(time.RFC3339),
		"total":            state.Total,
		"applied":          state.Applied,
		"unchanged":        state.Unchanged,
		"failed":           state.Failed,
		"skipped":          state.Skipped,
		"current_source":   state.Current,
		"progress_percent": math.Round(progress*10) / 10,
		"results":          state.Results,
	}
	if !state.CurrentStartedAt.IsZero() {
		view["current_started_at"] = state.CurrentStartedAt.Format(time.RFC3339)
	}
	if state.FinishedAt != nil {
		view["finished_at"] = state.FinishedAt.Format(time.RFC3339)
	}
	return view
}

func rulePlatformSyncStatus() map[string]interface{} {
	ruleSyncJob.mu.Lock()
	defer ruleSyncJob.mu.Unlock()
	return ruleSyncJobViewLocked()
}

func runRulePlatformSyncAll(cfg *Config, state *ruleSyncJobState, actorID int64, role auth.UserRole) {
	base := context.Background()
	base = context.WithValue(base, auth.UserContextKey, actorID)
	base = context.WithValue(base, auth.RoleContextKey, role)
	ctx, cancel := context.WithTimeout(base, 20*time.Minute)
	defer cancel()
	finish := func() {
		now := time.Now().UTC()
		ruleSyncJob.mu.Lock()
		state.Running = false
		state.FinishedAt = &now
		ruleSyncJob.mu.Unlock()
	}
	defer finish()

	sources, err := loadRulePlatformSources(ctx, cfg)
	if err != nil {
		ruleSyncJob.mu.Lock()
		state.Failed++
		state.Results = append(state.Results, map[string]interface{}{"source_id": "*", "status": "failed", "error": err.Error()})
		ruleSyncJob.mu.Unlock()
		return
	}

	updatable := make([]map[string]interface{}, 0, len(sources))
	for _, source := range sources {
		if asString(source["source_id"]) == "" {
			continue
		}
		if !asBoolDefault(source["updatable"], false) {
			// Local/built-in sources are not part of "sync" at all: they ship
			// with the product and must not appear as skipped noise.
			continue
		}
		if strings.TrimSpace(asString(source["url"])) == "" && !asBoolDefault(source["connector"], false) {
			continue
		}
		updatable = append(updatable, source)
	}

	ruleSyncJob.mu.Lock()
	state.Total = len(updatable)
	ruleSyncJob.mu.Unlock()

	for _, source := range updatable {
		sourceID := asString(source["source_id"])
		if ctx.Err() != nil {
			ruleSyncJob.mu.Lock()
			state.Failed++
			state.Results = append(state.Results, map[string]interface{}{"source_id": sourceID, "status": "failed", "error": "sync deadline reached"})
			ruleSyncJob.mu.Unlock()
			continue
		}
		ruleSyncJob.mu.Lock()
		state.Current = sourceID
		state.CurrentStartedAt = time.Now().UTC()
		ruleSyncJob.mu.Unlock()

		// The fetch layer has its own HTTP timeout; the source context must outlive
		// parse+convert+audit so a slow feed does not expire the audit write.
		sourceCtx, cancelSource := context.WithTimeout(ctx, 10*time.Minute)
		result, syncErr := syncRulePlatformSource(sourceCtx, cfg, map[string]interface{}{
			"source_id": sourceID,
			"version":   state.Version,
		})
		cancelSource()

		ruleSyncJob.mu.Lock()
		state.Current = ""
		state.CurrentStartedAt = time.Time{}
		switch {
		case syncErr != nil:
			state.Failed++
			state.Results = append(state.Results, map[string]interface{}{"source_id": sourceID, "status": "failed", "error": syncErr.Error()})
		case asString(result["status"]) == "unchanged":
			state.Unchanged++
			state.Results = append(state.Results, map[string]interface{}{"source_id": sourceID, "status": "unchanged", "endpoint": asString(result["endpoint"])})
		default:
			state.Applied++
			state.Results = append(state.Results, map[string]interface{}{"source_id": sourceID, "status": "applied", "endpoint": asString(result["endpoint"]), "rules": result["converted_count"]})
		}
		ruleSyncJob.mu.Unlock()
	}
}

func syncRulePlatformSource(ctx context.Context, cfg *Config, req map[string]interface{}) (map[string]interface{}, error) {
	if err := ensureRuleSourceCatalog(ctx, cfg); err != nil {
		return nil, err
	}
	sourceID := firstNonEmpty(asString(req["source_id"]), asString(req["id"]))
	if sourceID == "" {
		// "Sync rules" without a source means: sync every catalog source that
		// has a pinned upstream version. Per-source failures are reported, not
		// turned into one opaque error.
		return syncAllRulePlatformSources(ctx, cfg, req)
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
	version := strings.TrimSpace(asString(req["version"]))
	if version == "" {
		// A sync without an explicit pin means "fetch the current upstream
		// snapshot"; the version still has to be unique per run.
		version = "sync-" + time.Now().UTC().Format("20060102T150405Z")
	}
	// Discover/fetch audit entries use this pin revision as their resource.
	// Persist the generated version back into the request before materializing
	// the source, otherwise the audit entry has an empty resource and every
	// sync fails with "incomplete audit entry".
	req["version"] = version
	if asString(req["url"]) == "" {
		req["url"] = externalSourceURL(source, req)
	}
	// Build the ordered endpoint list once: primary first, GitHub mirrors after.
	if _, exists := req["endpoints"]; !exists {
		req["endpoints"] = githubMirrorEndpoints(asString(req["url"]))
	}
	if cfg.RuleLifecycle == nil {
		return nil, errors.New("secure rule lifecycle is unavailable")
	}
	actor := ruleLifecycleActor(ctx)
	inlineRequest := len(mapSlice(req["rules"])) > 0 || strings.TrimSpace(asString(req["content"])) != ""
	resource := sourceID + ":" + version
	if inlineRequest {
		if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.inline.attempt", resource, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"source_type": "local"}); err != nil {
			return nil, err
		}
	}
	rawRules, _, sourceDigest, sourceLocation, inline, err := rulePlatformSourceMaterial(ctx, cfg, actor, sourceID, req)
	if err != nil {
		if inlineRequest {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, inlineFailureStage(err), err); auditErr != nil {
				return nil, auditErr
			}
		}
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.sync", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	// Incremental apply: unchanged upstream bytes do not need another bundle
	// build or activation. This is what makes a 24h refresh cheap. The digest
	// includes the parser version, so a stricter parser forces one rebuild.
	contentDigest := rulePlatformContentDigest(sourceDigest)
	if !inlineRequest {
		var previousDigest string
		previousErr := cfg.DBPool.QueryRow(ctx, `SELECT content_hash FROM rule_source_versions WHERE source_id=$1 AND sync_status <> 'staged' ORDER BY synced_at DESC LIMIT 1`, sourceID).Scan(&previousDigest)
		if previousErr == nil && previousDigest == contentDigest {
			_, _ = cfg.DBPool.Exec(ctx, `UPDATE rule_source_versions SET synced_at=NOW(), sync_status='synced' WHERE source_id=$1 AND content_hash=$2`, sourceID, contentDigest)
			_ = cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.sync", sourceID+":"+version, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"unchanged": true, "digest": sourceDigest})
			return map[string]interface{}{
				"source_id": sourceID, "version": version, "content_hash": sourceDigest,
				"status": "unchanged", "activated": false, "endpoint": sourceLocation,
			}, nil
		}
	}

	if !validRulePlatformPathSegment(sourceID) || !validRulePlatformPathSegment(version) {
		if inlineRequest {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, "conflict", rulelifecycle.ErrRevision); auditErr != nil {
				return nil, auditErr
			}
		}
		return nil, rulelifecycle.ErrRevision
	}
	var existingDigest string
	existingErr := cfg.DBPool.QueryRow(ctx, `SELECT content_hash FROM rule_source_versions WHERE source_id=$1 AND version=$2`, sourceID, version).Scan(&existingDigest)
	if existingErr == nil && existingDigest != contentDigest {
		if inlineRequest {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, "conflict", rulelifecycle.ErrRevision); auditErr != nil {
				return nil, auditErr
			}
		}
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.persist", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": rulelifecycle.ErrRevision.Error(), "existing_digest": existingDigest, "candidate_digest": sourceDigest}); auditErr != nil {
			return nil, auditErr
		}
		return nil, rulelifecycle.ErrRevision
	}
	if existingErr != nil && !errors.Is(existingErr, pgx.ErrNoRows) {
		return nil, existingErr
	}
	if len(rawRules) == 0 {
		err := errors.New("rule source produced no strictly parseable rules")
		if inline {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, "parse", err); auditErr != nil {
				return nil, auditErr
			}
		}
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.parse", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.parse", sourceID+":"+version, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"digest": sourceDigest, "rule_count": len(rawRules), "source": sourceLocation}); err != nil {
		return nil, err
	}
	converted, report := convertRulePlatformRules(source, version, rawRules)
	lifecycleRevision := slugifyRulePlatformID(sourceID + "-" + version)
	runtimeRules := make([]compiledRuntimeRule, 0, len(converted))
	for _, convertedRule := range converted {
		if asString(convertedRule["support_level"]) == "unsupported" {
			continue
		}
		rawRule, err := json.Marshal(convertedRule)
		if err != nil {
			return nil, fmt.Errorf("marshal converted rule: %w", err)
		}
		runtimeRule, err := compileDetectionRule(asString(convertedRule["id"]), asString(convertedRule["category"]), asString(convertedRule["name"]), string(rawRule))
		if err != nil || !compiledRuntimeRuleValid(runtimeRule) {
			if err == nil {
				err = errors.New("converted rule failed strict validation")
			}
			previousSupport := firstNonEmpty(asString(convertedRule["support_level"]), "full_supported")
			if report.SupportCounts[previousSupport] > 0 {
				report.SupportCounts[previousSupport]--
			}
			report.SupportCounts["unsupported"]++
			report.Unsupported++
			convertedRule["support_level"] = "unsupported"
			convertedRule["support_notes"] = []string{"runtime_compile: " + err.Error()}
			continue
		}
		runtimeRules = append(runtimeRules, runtimeRule)
	}
	if len(runtimeRules) == 0 {
		return nil, errors.New("rule source produced no runtime-compatible rules")
	}
	// Respect operator decisions: a rule disabled in the console must not come
	// back just because the upstream source was synced again. A source with no
	// rows yet is new, not "everything disabled".
	allowed, known, err := enabledRuntimeRuleIDs(ctx, cfg, sourceID)
	if err != nil {
		return nil, err
	}
	disabledByOperator := 0
	if known {
		kept := runtimeRules[:0]
		for _, rule := range runtimeRules {
			if allowed[rule.ID] || allowed[sourceID+"-"+rule.ID] {
				kept = append(kept, rule)
			}
		}
		disabledByOperator = len(runtimeRules) - len(kept)
		if len(kept) == 0 {
			return nil, errors.New("every rule from this source is disabled in the console")
		}
		runtimeRules = kept
	}
	if err := ensureDefaultDetectionRules(ctx, cfg); err != nil {
		return nil, err
	}
	// Build from the database, not from the currently active bundle: rules
	// removed from detection_rules must not survive a sync through the old
	// bundle's base set.
	baseRules, err := loadEnabledDetectionRulesExcludingSource(ctx, cfg, sourceID)
	if err != nil {
		return nil, err
	}
	runtimeRules = mergeCompiledRuntimeRules(baseRules, runtimeRules)
	bundleData, err := json.Marshal(compiledBundleFile{Version: lifecycleRevision, Rules: runtimeRules})
	if err != nil {
		return nil, err
	}
	bundleDigestBytes := sha256.Sum256(bundleData)
	bundleDigest := hex.EncodeToString(bundleDigestBytes[:])
	preview, err := cfg.RuleLifecycle.StageLocal(ctx, actor, rulelifecycle.LocalSource{SourceID: sourceID, Revision: lifecycleRevision, SHA256: bundleDigest, Content: bundleData})
	if err != nil {
		if inline {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, inlineFailureStage(err), err); auditErr != nil {
				return nil, auditErr
			}
		}
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.sync", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	snapshot := map[string]interface{}{
		"source": map[string]interface{}{
			"id": source["id"], "name": source["name"], "category": source["category"], "origin": source["origin"],
			"license": source["license"], "url": source["url"], "bundled": source["bundled"], "connector": source["connector"],
			"restricted": source["restricted"], "updatable": source["updatable"],
		},
		"version":            version,
		"mode":               firstNonEmpty(asString(req["mode"]), "sync_convert"),
		"source_type":        map[bool]string{true: "local", false: "remote"}[inline],
		"source_location":    sourceLocation,
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
	snapshotForDisk["source_revision"] = version
	snapshotForDisk["source_content_digest"] = sourceDigest
	data, err := json.MarshalIndent(snapshotForDisk, "", "  ")
	if err != nil {
		if inline {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, "persistence", err); auditErr != nil {
				return nil, auditErr
			}
		}
		return nil, err
	}
	snapshotPath := filepath.Join("rules/security-engine/sources", sourceID, version, sourceDigest+".json")
	if err := writeImmutableRuleSnapshot(snapshotPath, data); err != nil {
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.persist", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_source_versions (source_id, version, content_hash, snapshot_path, sync_status, synced_at) VALUES ($1,$2,$3,$4,'staged',NOW()) ON CONFLICT (source_id, version) DO NOTHING`, sourceID, version, contentDigest, snapshotPath); err != nil {
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.persist", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	inserted, duplicates, unsupported, err := upsertConvertedDetectionRules(ctx, cfg, sourceID, converted)
	if err != nil {
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.persist", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	report.Inserted = inserted
	report.Duplicates += duplicates
	report.Unsupported = unsupported
	if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.persist", sourceID+":"+version, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"digest": sourceDigest, "snapshot_path": snapshotPath}); err != nil {
		return nil, err
	}

	// Sync applies immediately: the operator asked for "sync", and the staged
	// snapshot would otherwise sit unused. Every activation is recorded in the
	// lifecycle audit, and a bad source can be rolled back from the bundle list.
	manifest, err := cfg.RuleLifecycle.ActivateWithManifestCommit(ctx, actor, lifecycleRevision, func(candidate rulelifecycle.ActiveManifest) error {
		if cfg.RuleVersionStatus != nil {
			return cfg.RuleVersionStatus.MarkSynced(ctx, sourceID, version, contentDigest)
		}
		return commitSyncedRuleBundle(ctx, cfg, sourceID, version, contentDigest, candidate)
	})
	if err != nil {
		if inline {
			if auditErr := recordRuleInlineFailure(ctx, cfg, actor, resource, "persistence", err); auditErr != nil {
				return nil, auditErr
			}
		}
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.sync", sourceID+":"+version, rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, auditErr
		}
		return nil, err
	}
	if inline {
		if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.inline.outcome", resource, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"stage": "activated", "digest": sourceDigest, "active_digest": manifest.Digest}); err != nil {
			return nil, err
		}
		if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.inline", sourceID+":"+version, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"digest": sourceDigest, "active_digest": manifest.Digest}); err != nil {
			return nil, err
		}
	}
	if err := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.sync", sourceID+":"+version, rulelifecycle.AuditResultSucceeded, map[string]interface{}{"digest": sourceDigest, "active_digest": manifest.Digest}); err != nil {
		return nil, err
	}
	return map[string]interface{}{"source_id": sourceID, "version": version, "content_hash": sourceDigest, "snapshot_path": snapshotPath, "status": "applied", "activated": true, "endpoint": sourceLocation, "restricted": asBool(source["restricted"]), "license": asString(source["license"]), "rule_count": len(rawRules), "converted_count": report.Converted, "inserted_count": report.Inserted, "duplicate_count": report.Duplicates, "unsupported_count": report.Unsupported, "disabled_count": disabledByOperator, "support": report.SupportCounts, "dedup_report": report.DedupGroups, "bundle_hash": preview.Digest, "manifest_signature": manifest.Signature}, nil
}

func recordRuleInlineFailure(ctx context.Context, cfg *Config, actor rulelifecycle.Actor, resource, stage string, cause error) error {
	return cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.inline.outcome", resource, rulelifecycle.AuditResultFailed, map[string]interface{}{"stage": stage, "error_code": inlineFailureCode(cause)})
}

func inlineFailureStage(err error) string {
	switch {
	case errors.Is(err, rulelifecycle.ErrDigestMismatch):
		return "digest"
	case errors.Is(err, rulelifecycle.ErrSizeLimit):
		return "size"
	case errors.Is(err, rulelifecycle.ErrRevision):
		return "conflict"
	default:
		return "parse"
	}
}

func inlineFailureCode(err error) string {
	switch {
	case errors.Is(err, rulelifecycle.ErrDigestMismatch):
		return "digest_mismatch"
	case errors.Is(err, rulelifecycle.ErrSizeLimit):
		return "size_limit"
	case errors.Is(err, rulelifecycle.ErrRevision):
		return "revision_conflict"
	case errors.Is(err, rulelifecycle.ErrCompile):
		return "compile_failed"
	default:
		return "inline_failed"
	}
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
		{"id": "custom-rasp-rules", "name": "Custom RASP Rules", "category": "rasp", "origin": "user_provided", "license": "User-Provided", "url": "", "bundled": false, "connector": false, "restricted": false, "updatable": false},
		{"id": "sigma-connector", "name": "Sigma Rules Connector", "category": "log_audit", "origin": "external_subscription", "license": "Detection Rule License", "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/linux/builtin/sshd/lnx_sshd_susp_ssh.yml", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "sigma-full", "name": "SigmaHQ Sigma (full, medium+)", "category": "log_audit", "origin": "external_subscription", "license": "Detection Rule License", "url": "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "falco-connector", "name": "Falco Rules Connector", "category": "runtime", "origin": "external_subscription", "license": "Apache-2.0", "url": "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "et-open-connector", "name": "Emerging Threats Open Connector", "category": "traffic", "origin": "external_subscription", "license": "ET Open", "url": "https://rules.emergingthreats.net/open/suricata/emerging-all.rules", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "oisf-trafficid", "name": "OISF Traffic ID", "category": "traffic", "origin": "external_subscription", "license": "MIT", "url": "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules", "bundled": false, "connector": true, "restricted": false, "updatable": true},
		{"id": "stamus-lateral", "name": "Stamus Lateral Movement Rules", "category": "traffic", "origin": "external_subscription", "license": "GPL-3.0-or-later", "url": "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz", "bundled": false, "connector": true, "restricted": false, "updatable": true},
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
		if _, err := cfg.DBPool.Exec(ctx, `INSERT INTO rule_source_versions (source_id, version, content_hash, snapshot_path, sync_status, synced_at) VALUES ($1,$2,$3,$4,'synced',NOW()) ON CONFLICT (source_id, version) DO NOTHING`, row["id"], version, hash, snapshotPath); err != nil {
			return err
		}
	}
	return nil
}

func rulePlatformSourceMaterial(ctx context.Context, cfg *Config, actor rulelifecycle.Actor, sourceID string, req map[string]interface{}) ([]map[string]interface{}, []byte, string, string, bool, error) {
	if rules := mapSlice(req["rules"]); len(rules) > 0 {
		content, err := json.Marshal(rules)
		if err != nil {
			return nil, nil, "", "", true, fmt.Errorf("marshal inline rules: %w", err)
		}
		if len(content) > 64<<20 {
			return nil, nil, "", "", true, rulelifecycle.ErrSizeLimit
		}
		digest, err := verifyCallerDigest(content, req)
		if err != nil {
			return nil, nil, "", "", true, err
		}
		return rules, content, digest, "local://" + sourceID, true, nil
	}
	if inline := asString(req["content"]); strings.TrimSpace(inline) != "" {
		content := []byte(inline)
		if len(content) > 64<<20 {
			return nil, nil, "", "", true, rulelifecycle.ErrSizeLimit
		}
		digest, err := verifyCallerDigest(content, req)
		if err != nil {
			return nil, nil, "", "", true, err
		}
		return parseExternalRuleSource(sourceID, inline), content, digest, "local://" + sourceID, true, nil
	}
	switch sourceID {
	case "lyflow-compiled-local":
		rules := loadLocalCompiledRuleCorpus()
		content, err := json.Marshal(rules)
		if err != nil {
			return nil, nil, "", "", false, err
		}
		digest := sha256.Sum256(content)
		return rules, content, hex.EncodeToString(digest[:]), "local://compiled-corpus", false, nil
	case "custom-rasp-rules":
		return nil, nil, "", "", false, errors.New("custom rule sync requires pinned inline rules or content")
	}
	sourceURL := asString(req["url"])
	endpoints := rulePlatformStringSlice(req["endpoints"])
	if len(endpoints) == 0 && sourceURL != "" {
		endpoints = []string{sourceURL}
	}
	if len(endpoints) == 0 {
		return nil, nil, "", "", false, errors.New("external rule source URL is required")
	}
	checksum := firstNonEmpty(asString(req["sha256"]), asString(req["checksum"]), asString(req["content_hash"]))
	if cfg.RuleLifecycle == nil {
		return nil, nil, "", "", false, errors.New("secure rule lifecycle is unavailable")
	}
	var fetched rulelifecycle.FetchedSource
	var lastErr error
	for _, endpoint := range endpoints {
		pin := rulelifecycle.SourcePin{URL: endpoint, Revision: asString(req["version"]), SHA256: checksum}
		var err error
		if checksum == "" {
			fetched, err = cfg.RuleLifecycle.DiscoverSource(ctx, actor, pin)
			checksum = fetched.Pin.SHA256
		} else {
			fetched, err = cfg.RuleLifecycle.FetchSource(ctx, actor, pin)
		}
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		fetched = rulelifecycle.FetchedSource{}
	}
	if lastErr != nil {
		return nil, nil, "", "", false, fmt.Errorf("all endpoints failed (last: %w)", lastErr)
	}
	content, err := decodeRuleSourceBody(fetched.Content)
	if err != nil {
		if auditErr := cfg.RuleLifecycle.RecordOutcome(ctx, actor, "rule.source.parse", sourceID+":"+asString(req["version"]), rulelifecycle.AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return nil, nil, "", "", false, auditErr
		}
		return nil, nil, "", "", false, err
	}
	rules := parseExternalRuleSource(sourceID, content)
	return rules, fetched.Content, strings.ToLower(checksum), fetched.FinalURL, false, nil
}

func verifyCallerDigest(content []byte, req map[string]interface{}) (string, error) {
	expectedHex := strings.ToLower(firstNonEmpty(asString(req["sha256"]), asString(req["checksum"]), asString(req["content_hash"])))
	expected, err := hex.DecodeString(expectedHex)
	if err != nil || len(expected) != sha256.Size {
		return "", rulelifecycle.ErrDigestMismatch
	}
	actual := sha256.Sum256(content)
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return "", rulelifecycle.ErrDigestMismatch
	}
	return expectedHex, nil
}

func externalSourceURL(source map[string]interface{}, req map[string]interface{}) string {
	return firstNonEmpty(asString(req["url"]), asString(source["url"]))
}

// githubMirrorEndpoints returns the primary URL plus the mirrors we trust for
// GitHub-hosted rule content. The order is the order we try: raw first (most
// current), then CDN/mirrors for networks where GitHub is slow or blocked.
func githubMirrorEndpoints(primary string) []string {
	primary = strings.TrimSpace(primary)
	if primary == "" {
		return nil
	}
	parsed, err := url.Parse(primary)
	if err != nil {
		return []string{primary}
	}
	out := []string{primary}
	switch strings.ToLower(parsed.Hostname()) {
	case "raw.githubusercontent.com":
		parts := strings.SplitN(strings.TrimPrefix(parsed.Path, "/"), "/", 4)
		if len(parts) == 4 && parts[0] != "" && parts[1] != "" && parts[2] != "" && parts[3] != "" {
			out = append(out,
				"https://cdn.jsdelivr.net/gh/"+parts[0]+"/"+parts[1]+"@"+parts[2]+"/"+parts[3],
				"https://raw.gitmirror.com/"+parts[0]+"/"+parts[1]+"/"+parts[2]+"/"+parts[3],
			)
		}
		out = append(out, "https://ghproxy.net/"+primary, "https://gh-proxy.com/"+primary)
	case "codeload.github.com":
		out = append(out, "https://ghproxy.net/"+primary, "https://gh-proxy.com/"+primary)
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(out))
	for _, candidate := range out {
		if candidate != "" && !seen[candidate] {
			seen[candidate] = true
			unique = append(unique, candidate)
		}
	}
	return unique
}

func decodeRuleSourceBody(body []byte) (string, error) {
	const maxDecodedSize = 64 << 20
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		defer gz.Close()
		data, err := io.ReadAll(io.LimitReader(gz, maxDecodedSize+1))
		if err != nil {
			return "", err
		}
		if len(data) > maxDecodedSize {
			return "", errors.New("decoded rule source exceeds 64 MiB")
		}
		if text, ok, err := readRuleTarText(data, maxDecodedSize); err != nil {
			return "", err
		} else if ok {
			return text, nil
		}
		return string(data), nil
	}
	if text, ok, err := readRuleTarText(body, maxDecodedSize); err != nil {
		return "", err
	} else if ok {
		return text, nil
	}
	return string(body), nil
}

func readRuleTarText(data []byte, maxBytes int64) (string, bool, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var b strings.Builder
	readAny := false
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false, nil
		}
		if header == nil || header.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.ToLower(header.Name)
		yamlDoc := strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
		if !yamlDoc && !strings.HasSuffix(name, ".rules") && !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".txt") {
			continue
		}
		remaining := maxBytes - int64(b.Len())
		if remaining <= 0 || header.Size > remaining {
			return "", false, errors.New("archived rule source exceeds 64 MiB")
		}
		chunk, err := io.ReadAll(io.LimitReader(tr, remaining+1))
		if err != nil {
			return "", false, err
		}
		if int64(len(chunk)) > remaining {
			return "", false, errors.New("archived rule source exceeds 64 MiB")
		}
		if yamlDoc {
			b.WriteString("\n---\n")
		} else {
			b.WriteByte('\n')
		}
		b.Write(chunk)
		readAny = true
	}
	return b.String(), readAny, nil
}

func parseExternalRuleSource(sourceID, content string) []map[string]interface{} {
	switch sourceID {
	case "openrasp-derived":
		return parseOpenRASPRules(content)
	case "owasp-crs-connector":
		return parseOWASPCRSRules(content)
	case "sigma-connector", "sigma-full":
		return parseSigmaRules(content)
	case "falco-connector":
		return parseFalcoRules(content)
	case "et-open-connector":
		return parseSuricataRules(content, "et-open")
	case "suricata-et-open":
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
		if pattern == "" || isMatchAllRegex(pattern) {
			// A rule without a usable pattern (or one that matches every
			// event, such as the truncated "(?i)") is not a detector. Skip it
			// instead of importing a match-all alert generator.
			continue
		}
		operator := "regex"
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
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(block), "SecRule"))
	_, rest = nextModSecurityToken(rest)
	operator, _ := nextModSecurityToken(rest)
	operator = strings.TrimSpace(operator)
	switch {
	case strings.HasPrefix(operator, "@rx "):
		return strings.TrimSpace(operator[len("@rx "):])
	case strings.HasPrefix(operator, "@contains "):
		return strings.TrimSpace(operator[len("@contains "):])
	default:
		// @detectSQLi and other non-regex operators are not translated; the
		// caller skips the rule rather than inventing a pattern.
		return ""
	}
}

// nextModSecurityToken reads one quoted or bare token from a SecRule
// directive. Quoted tokens may contain escaped quotes, which is exactly where
// the previous "(.+?)(?:\\|\")" regex truncated OWASP patterns.
func nextModSecurityToken(input string) (string, string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", ""
	}
	if input[0] != '"' {
		index := strings.IndexAny(input, " \t")
		if index < 0 {
			return input, ""
		}
		return input[:index], strings.TrimSpace(input[index:])
	}
	var builder strings.Builder
	escaped := false
	for index := 1; index < len(input); index++ {
		char := input[index]
		if escaped {
			switch char {
			case '"':
				builder.WriteByte('"')
			default:
				builder.WriteByte('\\')
				builder.WriteByte(char)
			}
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			return builder.String(), strings.TrimSpace(input[index+1:])
		}
		builder.WriteByte(char)
	}
	return builder.String(), ""
}

func isMatchAllRegex(pattern string) bool {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return true
	}
	if compiled.MatchString("") {
		return true
	}
	switch strings.TrimSpace(pattern) {
	case "", "(?i)", "(?i).*", ".*", "^", "$":
		return true
	default:
		return false
	}
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
		logsource := mapValue(doc["logsource"])
		product := strings.ToLower(asString(logsource["product"]))
		service := strings.ToLower(asString(logsource["service"]))
		logCategory := strings.ToLower(asString(logsource["category"]))
		// Only telemetry LyFlow actually collects: Linux auth/audit and web
		// access logs. Anything whose logsource names another product is
		// excluded explicitly, because process_creation alone is used by
		// Windows/macOS rules too.
		switch product {
		case "windows", "macos", "azure", "aws", "gcp", "m365", "okta",
			"cisco", "fortinet", "paloalto", "zeek", "suricata", "proxy":
			continue
		}
		allowed := false
		switch {
		case product == "linux" || product == "unix":
			allowed = true
		case product == "" && (service == "sshd" || service == "auditd" || service == "nginx" || service == "apache" || service == "cron" || service == "sudo"):
			allowed = true
		case product == "" && logCategory == "webserver":
			allowed = true
		}
		if !allowed {
			continue
		}
		condition := strings.ToLower(asString(detection["condition"]))
		if strings.Contains(condition, "not ") {
			// The converter cannot express Sigma's negative selection; a rule
			// that includes a filter must not be turned into a positive match.
			continue
		}
		conditions := sigmaConditions(detection)
		if len(conditions) == 0 {
			continue
		}
		usable := false
		dangerous := false
		specific := false
		for _, condition := range conditions {
			if sigmaConditionHasWeakAlternation(condition) {
				dangerous = true
				break
			}
			field := asString(condition["field"])
			value := strings.TrimSpace(asString(condition["value"]))
			if field == "" || value == "" {
				dangerous = true
				break
			}
			usable = true
			if sigmaConditionValueIsSpecific(field, value) {
				specific = true
			}
		}
		if !usable || dangerous || !specific {
			continue
		}
		if len(out) >= 400 {
			break
		}
		category := "log_audit"
		if strings.Contains(logCategory, "process") {
			category = "runtime"
		}
		level := strings.ToLower(strings.TrimSpace(asString(doc["level"])))
		if level == "low" || level == "informational" || level == "info" {
			continue
		}
		out = append(out, map[string]interface{}{"id": "sigma-" + slugifyRulePlatformID(firstNonEmpty(asString(doc["id"]), asString(doc["title"]), fmt.Sprintf("rule-%d", i))), "name": firstNonEmpty(asString(doc["title"]), "Sigma Rule"), "category": category, "severity": sigmaLevel(asString(doc["level"])), "stage_hint": sigmaStage(stringSliceFromInterface(doc["tags"])), "field": defaultRuleField(category), "operator": "contains", "value": firstNonEmpty(asString(doc["title"]), "sigma"), "conditions": conditions, "source_operator": "sigma_yaml", "candidate": true})
	}
	return out
}

// sigmaConditions keeps Sigma's boolean shape. A selection is a set of field
// matches that must all hold, so flattening it into one "a|b|c" regex turns an
// AND into an OR: "GET" alone then matches every web log line. Only genuine
// alternatives (keyword lists, "1 of them") become a regex, and each branch
// must still be distinctive.
func sigmaConditions(detection map[string]interface{}) []map[string]interface{} {
	condition := strings.ToLower(strings.TrimSpace(asString(detection["condition"])))
	selections := map[string][]map[string]interface{}{}
	keys := make([]string, 0, len(detection))
	for key, value := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}
		lower := strings.ToLower(key)
		keys = append(keys, lower)
		selections[lower] = sigmaSelectionConditions(value)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return nil
	}
	if selected, ok := selections[condition]; ok {
		// "condition: selection" requires every field of that selection.
		return selected
	}
	switch {
	case strings.Contains(condition, "all of "), strings.Contains(condition, " and "):
		out := []map[string]interface{}{}
		for _, key := range keys {
			out = append(out, selections[key]...)
		}
		return out
	case strings.Contains(condition, "1 of "), strings.Contains(condition, " or "):
		return sigmaOrSelections(selections, keys)
	}
	return nil
}

// sigmaOrSelections flattens genuine alternatives into one regex. It refuses
// selections that themselves hold several fields, because "one of (A and B)"
// is not representable as a single pattern.
func sigmaOrSelections(selections map[string][]map[string]interface{}, keys []string) []map[string]interface{} {
	values := []string{}
	field := ""
	for _, key := range keys {
		conditions := selections[key]
		if len(conditions) != 1 {
			return nil
		}
		condition := conditions[0]
		fieldName := asString(condition["field"])
		value := strings.TrimSpace(asString(condition["value"]))
		if fieldName == "" || value == "" || (field != "" && field != fieldName) {
			return nil
		}
		if !sigmaConditionValueIsSpecific(fieldName, value) {
			return nil
		}
		field = fieldName
		values = append(values, regexp.QuoteMeta(value))
	}
	if field == "" || len(values) == 0 {
		return nil
	}
	return []map[string]interface{}{{"field": field, "operator": "regex", "value": "(?i)(" + strings.Join(values, "|") + ")", "regex": true}}
}

func sigmaSelectionConditions(value interface{}) []map[string]interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		fields := make([]string, 0, len(typed))
		for field := range typed {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		out := []map[string]interface{}{}
		for _, field := range fields {
			mapped := mapSigmaField(field)
			if mapped == "" {
				// Dropping an unmapped field would silently weaken the rule.
				return nil
			}
			operator := sigmaOperator(field)
			switch raw := typed[field].(type) {
			case []interface{}:
				values := sigmaStringList(raw)
				if len(values) == 0 {
					continue
				}
				if len(values) == 1 {
					out = append(out, sigmaCondition(mapped, operator, values[0]))
					continue
				}
				alternation, ok := sigmaValueAlternation(mapped, values)
				if !ok {
					return nil
				}
				out = append(out, alternation)
			default:
				value := strings.Trim(sigmaScalarString(raw), "*")
				if value == "" || value == "*" {
					continue
				}
				out = append(out, sigmaCondition(mapped, operator, value))
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []interface{}:
		values := sigmaStringList(typed)
		if len(values) == 0 {
			return nil
		}
		if len(values) == 1 {
			return []map[string]interface{}{sigmaCondition("message", "contains", values[0])}
		}
		alternation, ok := sigmaValueAlternation("message", values)
		if !ok {
			return nil
		}
		return []map[string]interface{}{alternation}
	}
	return nil
}

func sigmaCondition(field, operator, value string) map[string]interface{} {
	return map[string]interface{}{"field": field, "operator": operator, "value": value}
}

func sigmaStringList(values []interface{}) []string {
	out := []string{}
	for _, item := range values {
		if value := strings.Trim(sigmaScalarString(item), "*"); value != "" && value != "*" {
			out = append(out, value)
		}
	}
	return out
}

// sigmaScalarString stringifies Sigma scalar values. Status codes and event
// IDs arrive as numbers; asString alone drops them and silently weakens a rule.
func sigmaScalarString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		if typed == math.Trunc(typed) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	}
	return ""
}

func sigmaValueAlternation(field string, values []string) (map[string]interface{}, bool) {
	branches := make([]string, 0, len(values))
	for _, value := range values {
		if !sigmaConditionValueIsSpecific(field, value) {
			return nil, false
		}
		branches = append(branches, regexp.QuoteMeta(value))
	}
	if len(branches) == 0 {
		return nil, false
	}
	return map[string]interface{}{"field": field, "operator": "regex", "value": "(?i)(" + strings.Join(branches, "|") + ")", "regex": true}, true
}

var genericLogValues = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true, "head": true,
	"options": true, "patch": true, "http": true, "https": true, "ok": true,
	"true": true, "false": true, "null": true, "none": true, "any": true,
}

var genericMessageWords = map[string]bool{
	"root": true, "admin": true, "user": true, "sudo": true, "sshd": true,
	"login": true, "error": true, "warning": true,
}

// sigmaConditionValueIsSpecific rejects values that would match almost every
// log line. The check only applies to free-text fields: a structured field
// such as user or status keeps its meaning even when the value is short.
func sigmaConditionValueIsSpecific(field, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	switch field {
	case "message", "cmdline", "path", "query", "payload", "url":
		lower := strings.ToLower(value)
		if genericLogValues[lower] || commonConvertedTokens[lower] || len(value) < 4 {
			return false
		}
		if field == "message" && (len(value) < 6 || genericMessageWords[lower] || isAllDigits(value)) {
			return false
		}
	}
	return true
}

// sigmaConditionHasWeakAlternation spots a regex that ORs a generic token into
// the pattern. One such branch makes the whole condition match everything, so
// the rule is dropped instead of being turned into a catch-all.
func sigmaConditionHasWeakAlternation(condition map[string]interface{}) bool {
	operator := strings.ToLower(strings.TrimSpace(asString(condition["operator"])))
	isRegex, _ := condition["regex"].(bool)
	if !isRegex && operator != "regex" {
		return false
	}
	value := asString(condition["value"])
	if !strings.Contains(value, "|") {
		return false
	}
	for _, branch := range strings.Split(value, "|") {
		for _, token := range alnumRunPattern.FindAllString(branch, -1) {
			lower := strings.ToLower(token)
			if genericLogValues[lower] || genericMessageWords[lower] || commonConvertedTokens[lower] {
				return true
			}
		}
	}
	return false
}

var alnumRunPattern = regexp.MustCompile(`[A-Za-z0-9_]+`)

func mapSigmaField(field string) string {
	base := strings.Split(field, "|")[0]
	switch strings.ToLower(base) {
	case "commandline", "process.command_line", "command", "exe", "comm", "image", "process.executable":
		return "cmdline"
	case "pam_message", "message", "keywords", "cs-user-agent", "cs-host", "cs-referer", "http.user_agent":
		return "message"
	case "cs-method", "method", "http.method", "request.method":
		// Web methods only appear inside the raw request line; keep them as a
		// message condition so the other fields stay ANDed with them.
		return "message"
	case "user", "user.name", "username", "uid":
		return "user"
	case "src_ip", "source.ip", "sourceip", "ip_address", "c-ip", "client.ip":
		return "src_ip"
	case "dst_ip", "destination.ip", "dest_ip", "s-ip":
		return "dst_ip"
	case "url", "request", "uri", "http.url", "cs-uri-stem", "cs-uri", "c-uri", "c-uri-stem", "cs-uri-query":
		return "path"
	case "status", "http.status_code", "sc-status":
		return "status"
	case "process_name", "process.name":
		return "process_name"
	default:
		// Unknown Sigma fields must not silently become "message contains":
		// that is how Windows EventID rules ended up matching everything.
		return ""
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

func isAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
	return map[string]interface{}{"id": ruleID, "name": firstNonEmpty(asString(raw["name"]), ruleID), "category": category, "severity": severity, "score_hint": firstNonZero(asInt(raw["score_hint"]), int(severityBaseScore(severity))), "stage_hint": firstNonEmpty(asString(raw["stage_hint"]), inferRuleStage(category, asString(raw["name"])+" "+asString(raw["value"]))), "field": field, "operator": operator, "value": asString(raw["value"]), "regex": operator == "regex" || operator == "pcre", "candidate": asBoolDefault(raw["candidate"], true), "source_id": asString(source["id"]), "source_version": version, "source_license": asString(source["license"]), "source_url": asString(source["url"]), "upstream_id": firstNonEmpty(asString(raw["upstream_id"]), asString(raw["id"])), "conditions": mapSlice(raw["conditions"]), "window": mapValue(raw["window"]), "group_by": asString(raw["group_by"]),
		"source_dest_port": asString(raw["source_dest_port"]), "source_flow": asString(raw["source_flow"]), "source_match_options": raw["source_match_options"]}
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
	// Converted Suricata rules lose their companion options. A pattern without
	// a distinctive literal then matches almost everything (for example the
	// ET "GET" / PT "POST" / Snort ".php" rules), so never load it.
	if strings.EqualFold(asString(rule["category"]), "traffic") &&
		convertedTrafficRuleID(asString(rule["id"])) &&
		len(conditions) == 0 {
		if reason := convertedTrafficRuleRejection(rule, operator); reason != "" {
			return "unsupported", []string{reason}
		}
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

// enabledRuntimeRuleIDs returns the rule ids the operator has left enabled for
// one source, plus whether the source has any rows at all. A fresh source is
// "unknown" so sync does not mistake it for "everything disabled".
func enabledRuntimeRuleIDs(ctx context.Context, cfg *Config, sourceID string) (map[string]bool, bool, error) {
	rows, err := cfg.DBPool.Query(ctx, `SELECT id, enabled FROM detection_rules WHERE source_id=$1`, sourceID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	allowed := map[string]bool{}
	total := 0
	for rows.Next() {
		var id string
		var enabled bool
		if err := rows.Scan(&id, &enabled); err != nil {
			return nil, false, err
		}
		total++
		if !enabled {
			continue
		}
		allowed[id] = true
		// Stored ids are sourceID + "-" + converted id, and some converters
		// already prefix the id with the source. Index every shape so the
		// runtime id matches whichever form the database ended up with.
		allowed[strings.TrimPrefix(id, sourceID+"-")] = true
		allowed[sourceID+"-"+strings.TrimPrefix(id, sourceID+"-")] = true
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return allowed, total > 0, nil
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
	if cfg.RuleLifecycle == nil {
		return nil, errors.New("secure rule lifecycle is unavailable")
	}
	rows, err := loadRulePlatformBundles(ctx, cfg)
	if err != nil {
		return nil, err
	}
	active := ""
	candidates := make([]map[string]interface{}, 0, len(rows))
	var target map[string]interface{}
	for _, row := range rows {
		version := asString(row["version"])
		if row["status"] == "active" {
			active = version
			continue
		}
		if requestedVersion != "" && requestedVersion == version {
			target = row
		}
		if requestedVersion == "" {
			candidates = append(candidates, row)
		}
	}
	if requestedVersion == active {
		return nil, fmt.Errorf("bundle %s is already active", requestedVersion)
	}
	if requestedVersion == "" {
		if len(candidates) == 0 {
			return nil, fmt.Errorf("no rollback bundle available")
		}
		sort.Slice(candidates, func(i, j int) bool {
			return asString(candidates[i]["created_at"]) > asString(candidates[j]["created_at"])
		})
		target = candidates[0]
		requestedVersion = asString(target["version"])
	}
	if target == nil {
		// The signed lifecycle store is authoritative. Database rows are an index
		// and may be absent after migration from an older deployment.
		target = map[string]interface{}{"version": requestedVersion}
	}
	manifest, err := cfg.RuleLifecycle.RollbackWithManifestCommit(ctx, ruleLifecycleActor(ctx), requestedVersion, func(candidate rulelifecycle.ActiveManifest) error {
		tx, beginErr := cfg.DBPool.Begin(ctx)
		if beginErr != nil {
			return beginErr
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, updateErr := tx.Exec(ctx, `UPDATE rule_bundles SET status='inactive' WHERE status='active'`); updateErr != nil {
			return updateErr
		}
		if _, insertErr := tx.Exec(ctx, `INSERT INTO rule_bundles (version,status,bundle_hash,bundle_path,activated_at) VALUES ($1,'active',$2,$3,NOW()) ON CONFLICT (version) DO UPDATE SET status='active', bundle_hash=EXCLUDED.bundle_hash, bundle_path=EXCLUDED.bundle_path, activated_at=NOW()`, requestedVersion, candidate.Digest, candidate.BundlePath); insertErr != nil {
			return insertErr
		}
		if _, eventErr := tx.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version,target,status,message) VALUES ($1,$2,$3,$4)`, requestedVersion, "ly-security-engine", "rollback_ok", "rolled back from "+active); eventErr != nil {
			return eventErr
		}
		return tx.Commit(ctx)
	})
	if err != nil {
		_, _ = cfg.DBPool.Exec(ctx, `INSERT INTO rule_hot_reload_events (bundle_version, target, status, message) VALUES ($1,$2,$3,$4)`, requestedVersion, "ly-security-engine", "rollback_failed", err.Error())
		return nil, err
	}
	target["status"] = "active"
	target["rollback_from"] = active
	target["bundle_hash"] = manifest.Digest
	target["bundle_path"] = manifest.BundlePath
	target["manifest_signature"] = manifest.Signature
	target["reload"] = map[string]interface{}{"status": "ok", "message": manifest.BundlePath}
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
