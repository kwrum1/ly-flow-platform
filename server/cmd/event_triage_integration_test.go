package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

// P0-7 regression. Before this feature threat_events had no triage state and no
// asset linkage: measured on the mirror sensor, asset_id was bound on 0 of
// 11,836 events and disposal status was set on 0 of 11,836.
func TestEventTriageUpdatesAndBindsAssets(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	cfg := seedTriageStore(t, ctx, pool)

	// When: one bulk decision over three events, two of which are on internal
	// hosts that exist only as traffic (no asset inventory rows).
	result, err := applyEventTriage(ctx, cfg,
		[]string{"p0-7-a", "p0-7-b", "p0-7-c"},
		triageStatusTruePositive, "confirmed exploit attempt", "user:7", true)
	if err != nil {
		t.Fatalf("apply triage: %v", err)
	}

	// Then
	if result.Updated != 3 {
		t.Fatalf("updated=%d, want 3", result.Updated)
	}
	if result.AssetsBound != 3 {
		t.Fatalf("assets bound=%d, want 3", result.AssetsBound)
	}
	if len(result.UnknownEvents) != 0 {
		t.Fatalf("unknown events=%v", result.UnknownEvents)
	}

	// Every event must now carry a non-null asset and the decision.
	var bound, triaged int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM threat_events
		WHERE triage_status=$1 AND asset_id IS NOT NULL`, triageStatusTruePositive).Scan(&triaged); err != nil {
		t.Fatalf("count triaged: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM threat_events WHERE asset_id IS NOT NULL`).Scan(&bound); err != nil {
		t.Fatalf("count bound: %v", err)
	}
	if triaged != 3 || bound != 3 {
		t.Fatalf("triaged=%d bound=%d, want 3/3", triaged, bound)
	}

	// assets was empty before this call; the derivation must have created rows
	// for the internal endpoints so the binding points at something real.
	var assets int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM assets WHERE 'auto-derived' = ANY(tags)`).Scan(&assets); err != nil {
		t.Fatalf("count derived assets: %v", err)
	}
	if assets == 0 {
		t.Fatal("no derived asset rows; asset_id would dangle")
	}
}

// A repeated decision on the same events is idempotent and must not duplicate
// derived asset rows or reassign a different asset.
func TestEventTriageIsIdempotent(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	cfg := seedTriageStore(t, ctx, pool)
	uids := []string{"p0-7-idem-a", "p0-7-idem-b"}

	// When
	if _, err := applyEventTriage(ctx, cfg, uids, triageStatusFalsePositive, "noise", "user:7", true); err != nil {
		t.Fatalf("first triage: %v", err)
	}
	var assetsAfterFirst int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM assets`).Scan(&assetsAfterFirst); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	firstIDs := eventAssetIDs(t, ctx, pool, uids)

	second, err := applyEventTriage(ctx, cfg, uids, triageStatusClosed, "archived", "user:8", true)
	if err != nil {
		t.Fatalf("second triage: %v", err)
	}

	// Then
	var assetsAfterSecond int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM assets`).Scan(&assetsAfterSecond); err != nil {
		t.Fatalf("count assets: %v", err)
	}
	if assetsAfterSecond != assetsAfterFirst {
		t.Fatalf("asset rows grew on replay: %d -> %d", assetsAfterFirst, assetsAfterSecond)
	}
	secondIDs := eventAssetIDs(t, ctx, pool, uids)
	for uid, id := range firstIDs {
		if secondIDs[uid] != id {
			t.Fatalf("asset for %s changed on replay: %s -> %s", uid, id, secondIDs[uid])
		}
	}
	if second.Updated != 2 {
		t.Fatalf("updated=%d, want 2", second.Updated)
	}
}

// Re-classifying without bind_assets must not re-resolve an asset that was
// already bound, because a manual binding would otherwise be overwritten.
func TestEventTriageWithoutBindLeavesAssetUntouched(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	cfg := seedTriageStore(t, ctx, pool)
	uids := []string{"p0-7-keep-a"}
	if _, err := applyEventTriage(ctx, cfg, uids, triageStatusTriaged, "", "user:7", true); err != nil {
		t.Fatalf("initial bind: %v", err)
	}
	before := eventAssetIDs(t, ctx, pool, uids)

	// When
	result, err := applyEventTriage(ctx, cfg, uids, triageStatusFalsePositive, "fp", "user:8", false)
	if err != nil {
		t.Fatalf("second triage: %v", err)
	}

	// Then
	if result.AssetsBound != 0 {
		t.Fatalf("assets bound=%d, want 0 when bind_assets is false", result.AssetsBound)
	}
	after := eventAssetIDs(t, ctx, pool, uids)
	if before[uids[0]] != after[uids[0]] {
		t.Fatalf("asset changed despite bind_assets=false: %s -> %s", before[uids[0]], after[uids[0]])
	}
}

// The HTTP boundary must reject unknown statuses and empty id lists instead of
// writing a state the rest of the system cannot interpret.
func TestEventTriageHTTPRejectsInvalidInput(t *testing.T) {
	pool, ctx := xdrMigrationTestPool(t)
	cfg := seedTriageStore(t, ctx, pool)
	handler := eventsTriageHandler(cfg)
	serve := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/events/triage", strings.NewReader(body))
		request = request.WithContext(context.WithValue(request.Context(), auth.UserContextKey, int64(7)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	if code := serve(`{"event_uids":["p0-7-a"],"status":"maybe"}`).Code; code != http.StatusBadRequest {
		t.Fatalf("unknown status code=%d, want 400", code)
	}
	if code := serve(`{"event_uids":[],"status":"triaged"}`).Code; code != http.StatusBadRequest {
		t.Fatalf("empty event_uids code=%d, want 400", code)
	}
	if code := serve(`{"event_uids":["p0-7-a"],"status":"triaged","bogus":1}`).Code; code != http.StatusBadRequest {
		t.Fatalf("unknown field code=%d, want 400", code)
	}

	// A valid request reports success and the applied state.
	response := serve(`{"event_uids":["p0-7-a"],"status":"triaged","reason":"reviewed","bind_assets":true}`)
	if response.Code != http.StatusOK {
		t.Fatalf("valid request code=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data triageResult `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.Updated != 1 || payload.Data.Status != triageStatusTriaged {
		t.Fatalf("result=%+v", payload.Data)
	}
}

// Unknown ids must be reported rather than silently counted as updated.
func TestEventTriageReportsUnknownEvents(t *testing.T) {
	pool, ctx := xdrMigrationTestPool(t)
	cfg := seedTriageStore(t, ctx, pool)
	result, err := applyEventTriage(ctx, cfg,
		[]string{"p0-7-a", "does-not-exist"}, triageStatusTriaged, "", "user:7", false)
	if err != nil {
		t.Fatalf("apply triage: %v", err)
	}
	if result.Updated != 1 {
		t.Fatalf("updated=%d, want 1", result.Updated)
	}
	if len(result.UnknownEvents) != 1 || result.UnknownEvents[0] != "does-not-exist" {
		t.Fatalf("unknown events=%v", result.UnknownEvents)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func eventAssetIDs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uids []string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(uids))
	rows, err := pool.Query(ctx, `SELECT event_uid, COALESCE(asset_id::text,'') FROM threat_events WHERE event_uid = ANY($1)`, uids)
	if err != nil {
		t.Fatalf("load asset ids: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var uid, assetID string
		if err := rows.Scan(&uid, &assetID); err == nil {
			out[uid] = assetID
		}
	}
	return out
}

// seedTriageStore builds the minimum schema P0-7 touches.
func seedTriageStore(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *Config {
	t.Helper()
	for _, statement := range []string{
		`DROP TABLE IF EXISTS threat_events`,
		`DROP TABLE IF EXISTS assets`,
		`DROP TABLE IF EXISTS agents`,
		`CREATE TABLE threat_events (
			event_uid VARCHAR(160) PRIMARY KEY,
			category VARCHAR(32) NOT NULL,
			severity VARCHAR(16) NOT NULL,
			source_engine VARCHAR(64),
			event_type VARCHAR(128),
			agent_id VARCHAR(128),
			src_ip VARCHAR(45),
			dst_ip VARCHAR(45),
			message TEXT,
			observed_at TIMESTAMPTZ NOT NULL,
			raw_event JSONB NOT NULL DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW())`,
		`CREATE TABLE assets (
			id BIGSERIAL PRIMARY KEY,
			hostname VARCHAR(255),
			ip INET,
			os VARCHAR(64),
			agent_id VARCHAR(64),
			tags TEXT[],
			first_seen TIMESTAMPTZ,
			last_seen TIMESTAMPTZ,
			metadata JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW())`,
		`CREATE TABLE agents (
			id BIGSERIAL PRIMARY KEY,
			uuid TEXT UNIQUE,
			hostname VARCHAR(255),
			ip INET,
			status VARCHAR(32))`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("seed schema: %v", err)
		}
	}
	// Three events: two internal-to-internal (asset must be derived), one
	// external source with an internal victim.
	seeds := []struct{ uid, src, dst string }{
		{"p0-7-a", "10.1.1.181", "10.1.18.253"},
		{"p0-7-b", "10.1.1.181", "10.1.18.254"},
		{"p0-7-c", "203.0.113.9", "10.1.18.253"},
		{"p0-7-idem-a", "10.1.1.181", "10.1.18.253"},
		{"p0-7-idem-b", "10.1.1.181", "10.1.18.254"},
		{"p0-7-keep-a", "10.1.1.181", "10.1.18.253"},
	}
	for _, seed := range seeds {
		if _, err := pool.Exec(ctx, `INSERT INTO threat_events
			(event_uid, category, severity, source_engine, event_type, agent_id, src_ip, dst_ip, message, observed_at, raw_event)
			VALUES ($1,'traffic','high','suricata','alert','local',$2,$3,'test event',NOW(),'{}'::jsonb)`,
			seed.uid, seed.src, seed.dst); err != nil {
			t.Fatalf("seed event %s: %v", seed.uid, err)
		}
	}
	cfg := &Config{DBPool: pool}
	if err := EnsureThreatEventTriageSchema(ctx, cfg); err != nil {
		t.Fatalf("ensure triage schema: %v", err)
	}
	return cfg
}
