package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

// P0-7: event-level triage and asset binding.
//
// Before this, threat_events had no triage state and no asset linkage at all:
// measured on the mirror sensor, asset_id was bound on 0 of 11,836 events and
// the disposal state was set on 0 of 11,836. An analyst could read an alert and
// had no way to record "this is real", "this is a false positive", or which
// host it belongs to, so every review was lost.
//
// The triage columns live on threat_events rather than in a side table because
// every list/detail query already reads that row; a join would have to be added
// to all of them.

const (
	triageStatusNew          = "new"
	triageStatusTriaged      = "triaged"
	triageStatusTruePositive = "true_positive"
	triageStatusFalsePositive = "false_positive"
	triageStatusClosed       = "closed"
)

// validTriageStatuses is the closed set accepted by the API. Anything else is
// rejected rather than stored, so a typo cannot silently create a new state.
var validTriageStatuses = map[string]bool{
	triageStatusNew:           true,
	triageStatusTriaged:       true,
	triageStatusTruePositive:  true,
	triageStatusFalsePositive: true,
	triageStatusClosed:        true,
}

// threatEventTriageColumns are added to the existing table on start.
var threatEventTriageColumns = []struct {
	Name    string
	Type    string
	Default string
}{
	{"triage_status", "VARCHAR(32)", "'" + triageStatusNew + "'"},
	{"triage_reason", "TEXT", "''"},
	{"triage_actor", "VARCHAR(64)", "''"},
	{"triaged_at", "TIMESTAMPTZ", ""},
	{"asset_id", "BIGINT", ""},
	{"asset_bound_at", "TIMESTAMPTZ", ""},
	{"asset_binding_source", "VARCHAR(32)", "''"},
}

// EnsureThreatEventTriageSchema is idempotent: ADD COLUMN IF NOT EXISTS plus a
// default backfill for rows that predate the columns.
func EnsureThreatEventTriageSchema(ctx context.Context, cfg *Config) error {
	if cfg == nil || cfg.DBPool == nil {
		return fmt.Errorf("triage database unavailable")
	}
	for _, column := range threatEventTriageColumns {
		definition := fmt.Sprintf("%s %s", column.Name, column.Type)
		if column.Default != "" {
			definition += " DEFAULT " + column.Default
		}
		statement := fmt.Sprintf("ALTER TABLE threat_events ADD COLUMN IF NOT EXISTS %s", definition)
		if _, err := cfg.DBPool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("add threat_events.%s: %w", column.Name, err)
		}
	}
	// Existing rows must read as "new", not as an empty string, otherwise
	// "unreviewed" and "unknown" become indistinguishable in the UI.
	if _, err := cfg.DBPool.Exec(ctx, `UPDATE threat_events SET triage_status = $1
		WHERE triage_status IS NULL OR triage_status = ''`, triageStatusNew); err != nil {
		return fmt.Errorf("backfill triage_status: %w", err)
	}
	if _, err := cfg.DBPool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_threat_events_triage
		ON threat_events (triage_status, observed_at DESC)`); err != nil {
		return fmt.Errorf("index triage_status: %w", err)
	}
	if _, err := cfg.DBPool.Exec(ctx, `CREATE INDEX IF NOT EXISTS idx_threat_events_asset
		ON threat_events (asset_id) WHERE asset_id IS NOT NULL`); err != nil {
		return fmt.Errorf("index asset_id: %w", err)
	}
	return nil
}

// triageRequest is the body accepted by POST /api/v1/events/triage.
type triageRequest struct {
	EventUIDs []string `json:"event_uids"`
	Status    string   `json:"status"`
	Reason    string   `json:"reason"`
	// BindAssets asks the handler to resolve an asset for every event it
	// touches. It is a separate flag because re-classifying an already-bound
	// event must not silently re-resolve its asset.
	BindAssets bool `json:"bind_assets"`
}

type triageResult struct {
	Requested     int      `json:"requested"`
	Updated       int      `json:"updated"`
	AssetsBound   int      `json:"assets_bound"`
	Status        string   `json:"status"`
	UnknownEvents []string `json:"unknown_events,omitempty"`
}

// eventsTriageHandler applies a triage decision to a set of events.
func eventsTriageHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if cfg == nil || cfg.DBPool == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "triage_unavailable", "triage store unavailable")
			return
		}
		var request triageRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_triage_request", err.Error())
			return
		}
		status := strings.ToLower(strings.TrimSpace(request.Status))
		if !validTriageStatuses[status] {
			writeJSONError(w, http.StatusBadRequest, "invalid_triage_status",
				fmt.Sprintf("status must be one of new/triaged/true_positive/false_positive/closed, got %q", request.Status))
			return
		}
		uids := sanitizeEventUIDs(request.EventUIDs)
		if len(uids) == 0 {
			writeJSONError(w, http.StatusBadRequest, "missing_event_uids", "event_uids must contain at least one non-empty id")
			return
		}
		if len(uids) > 5000 {
			writeJSONError(w, http.StatusBadRequest, "too_many_event_uids", "at most 5000 events per request")
			return
		}
		actor := fmt.Sprintf("user:%d", getUserIDFromRequest(r))
		result, err := applyEventTriage(r.Context(), cfg, uids, status, request.Reason, actor, request.BindAssets)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "triage_failed", err.Error())
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success", "data": result,
		}); err != nil {
			return
		}
	}
}

// applyEventTriage updates the triage columns for the given events, and
// optionally resolves and binds an asset for each.
func applyEventTriage(ctx context.Context, cfg *Config, uids []string, status, reason, actor string, bindAssets bool) (triageResult, error) {
	result := triageResult{Requested: len(uids), Status: status}
	now := time.Now().UTC()
	commandTag, err := cfg.DBPool.Exec(ctx, `
		UPDATE threat_events
		SET triage_status = $2,
		    triage_reason = $3,
		    triage_actor = $4,
		    triaged_at = $5,
		    updated_at = $5
		WHERE event_uid = ANY($1)`, uids, status, reason, actor, now)
	if err != nil {
		return result, fmt.Errorf("apply triage: %w", err)
	}
	result.Updated = int(commandTag.RowsAffected())
	if result.Updated < result.Requested {
		result.UnknownEvents = missingEventUIDs(ctx, cfg, uids)
	}
	if !bindAssets {
		return result, nil
	}
	bound, err := bindAssetsForEvents(ctx, cfg, uids, now)
	if err != nil {
		return result, err
	}
	result.AssetsBound = bound
	return result, nil
}

// bindAssetsForEvents resolves an asset for each event by matching the event's
// internal endpoint against assets, then agents, then a derived identity.
//
// assets is empty on this deployment (0 rows) and there is exactly one agent,
// so a JOIN-only implementation would bind nothing. The resolution order is
// therefore explicit and records which source produced the binding, so a later
// real asset inventory can be distinguished from a derived binding.
func bindAssetsForEvents(ctx context.Context, cfg *Config, uids []string, now time.Time) (int, error) {
	rows, err := cfg.DBPool.Query(ctx, `
		SELECT event_uid, src_ip, dst_ip, agent_id
		FROM threat_events WHERE event_uid = ANY($1)`, uids)
	if err != nil {
		return 0, fmt.Errorf("load events for asset binding: %w", err)
	}
	defer rows.Close()
	type pending struct {
		uid     string
		assetID int64
		source  string
	}
	bindings := make([]pending, 0, len(uids))
	for rows.Next() {
		var uid, srcIP, dstIP, agentID string
		if err := rows.Scan(&uid, &srcIP, &dstIP, &agentID); err != nil {
			continue
		}
		assetID, source, err := resolveEventAsset(ctx, cfg, srcIP, dstIP, agentID)
		if err != nil {
			return 0, err
		}
		if assetID == 0 {
			continue
		}
		bindings = append(bindings, pending{uid: uid, assetID: assetID, source: source})
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate events for asset binding: %w", err)
	}
	bound := 0
	for _, binding := range bindings {
		if _, err := cfg.DBPool.Exec(ctx, `
			UPDATE threat_events
			SET asset_id = $2, asset_bound_at = $3, asset_binding_source = $4, updated_at = $3
			WHERE event_uid = $1`, binding.uid, binding.assetID, now, binding.source); err != nil {
			return bound, fmt.Errorf("bind asset for %s: %w", binding.uid, err)
		}
		bound++
	}
	return bound, nil
}

// resolveEventAsset returns the asset id for an event, preferring the endpoint
// that is inside the protected range. The source label records how it was found.
func resolveEventAsset(ctx context.Context, cfg *Config, srcIP, dstIP, agentID string) (int64, string, error) {
	candidates := []string{}
	for _, ip := range []string{dstIP, srcIP} {
		normalized := normalizeAssetIP(ip)
		if normalized == "" || !isInternalAssetIP(normalized) {
			continue
		}
		candidates = append(candidates, normalized)
	}
	// 1. explicit asset inventory
	for _, ip := range candidates {
		var assetID int64
		err := cfg.DBPool.QueryRow(ctx,
			`SELECT id FROM assets WHERE host(ip) = $1 ORDER BY last_seen DESC NULLS LAST LIMIT 1`, ip).Scan(&assetID)
		if err == nil && assetID != 0 {
			return assetID, "asset_inventory", nil
		}
	}
	// 2. registered agent
	if trimmed := strings.TrimSpace(agentID); trimmed != "" && trimmed != "local" {
		var assetID int64
		if err := cfg.DBPool.QueryRow(ctx,
			`SELECT id FROM agents WHERE uuid = $1 LIMIT 1`, trimmed).Scan(&assetID); err == nil && assetID != 0 {
			return assetID, "agent_registry", nil
		}
	}
	for _, ip := range candidates {
		var assetID int64
		if err := cfg.DBPool.QueryRow(ctx,
			`SELECT id FROM agents WHERE host(ip) = $1 LIMIT 1`, ip).Scan(&assetID); err == nil && assetID != 0 {
			return assetID, "agent_registry", nil
		}
		// 3. derive a stable asset row for an internal endpoint that has traffic
		//    but no inventory record. Without this, an unmanaged host that is
		//    actively being attacked stays unattributable.
		derived, err := ensureDerivedAsset(ctx, cfg, ip)
		if err != nil {
			return 0, "", err
		}
		if derived != 0 {
			return derived, "derived_from_traffic", nil
		}
	}
	return 0, "", nil
}

// ensureDerivedAsset creates (or reuses) an assets row for an internal IP.
//
// The row is marked in metadata so a real inventory sync can recognise and
// upgrade it instead of creating a duplicate.
func ensureDerivedAsset(ctx context.Context, cfg *Config, ip string) (int64, error) {
	if ip == "" {
		return 0, nil
	}
	var existing int64
	if err := cfg.DBPool.QueryRow(ctx,
		`SELECT id FROM assets WHERE host(ip) = $1 ORDER BY last_seen DESC NULLS LAST LIMIT 1`, ip).Scan(&existing); err == nil && existing != 0 {
		return existing, nil
	}
	var assetID int64
	err := cfg.DBPool.QueryRow(ctx, `
		INSERT INTO assets (hostname, ip, os, tags, first_seen, last_seen, metadata, created_at)
		VALUES ($1, $2::inet, '', ARRAY['auto-derived']::text[], $3, $3,
		        jsonb_build_object('derived', true, 'source', 'traffic_events'), $3)
		RETURNING id`, "auto-"+ip, ip, time.Now().UTC()).Scan(&assetID)
	if err != nil {
		return 0, fmt.Errorf("derive asset for %s: %w", ip, err)
	}
	return assetID, nil
}

// normalizeAssetIP strips a port or CIDR suffix and validates the literal.
func normalizeAssetIP(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if parsed, _, err := net.ParseCIDR(trimmed); err == nil {
		return parsed.String()
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	if net.ParseIP(trimmed) == nil {
		return ""
	}
	return trimmed
}

// isInternalAssetIP limits derived assets to RFC1918 space so a public source
// address never becomes an "asset".
func isInternalAssetIP(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func sanitizeEventUIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || len(trimmed) > 160 {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func missingEventUIDs(ctx context.Context, cfg *Config, uids []string) []string {
	rows, err := cfg.DBPool.Query(ctx, `SELECT event_uid FROM threat_events WHERE event_uid = ANY($1)`, uids)
	if err != nil {
		return nil
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(uids))
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err == nil {
			found[uid] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for _, uid := range uids {
		if _, ok := found[uid]; !ok {
			missing = append(missing, uid)
		}
	}
	return missing
}

// getUserIDFromRequest reads the authenticated user id from the request context.
func getUserIDFromRequest(r *http.Request) int64 {
	if r == nil {
		return 0
	}
	return auth.GetUserIDFromContext(r.Context())
}
