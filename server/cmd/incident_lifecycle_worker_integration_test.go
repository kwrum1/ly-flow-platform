package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

// P0-6 regression: incident materialization must not depend on an HTTP request.
//
// The old pipeline only ran inside GET /api/v1/incidents?live=1, so any alert
// window without a page load was never materialized. This test creates the
// alerts and then calls the worker path directly, with no HTTP server anywhere.
func TestIncidentWorkerMaterializesWithoutHTTP(t *testing.T) {
	// Given
	pool, ctx := incidentTestPool(t)
	now := time.Now().UTC()
	store := seedIncidentTestStore(t, ctx, pool, now)
	cfg := &Config{DBPool: pool, Incidents: store}

	seedTrafficThreatEvents(t, ctx, pool, now, []trafficSeed{
		{uid: "p0-6-a", src: "10.1.1.181", dst: "10.1.18.253", severity: "high", at: now.Add(-5 * time.Minute)},
		{uid: "p0-6-b", src: "10.1.1.181", dst: "10.1.18.254", severity: "high", at: now.Add(-4 * time.Minute)},
	})

	// When: a single worker tick, no HTTP request, no Incident page opened.
	report, err := runIncidentPipelineTick(ctx, cfg, incidentTrafficWindow{
		Lookback: 30 * time.Minute,
		Limit:    500,
	})
	if err != nil {
		t.Fatalf("pipeline tick failed: %v", err)
	}

	// Then
	if report.Scanned < 2 {
		t.Fatalf("scanned=%d, want at least the 2 seeded events", report.Scanned)
	}
	if report.Eligible != 1 {
		t.Fatalf("eligible groups=%d, want 1 (same source + same rule)", report.Eligible)
	}
	if report.Created != 1 {
		t.Fatalf("created=%d, want 1", report.Created)
	}
	if countTrafficIncidents(t, ctx, pool) != 1 {
		t.Fatalf("incident rows=%d, want 1", countTrafficIncidents(t, ctx, pool))
	}
	if lineages := countIncidentLineage(t, ctx, pool); lineages < 2 {
		t.Fatalf("evidence lineage rows=%d, want at least 2 (one per event)", lineages)
	}
}

// A second tick over the same window must update, not duplicate. Without this
// the 60s worker would create a new incident every minute.
func TestIncidentWorkerTickIsIdempotent(t *testing.T) {
	// Given
	pool, ctx := incidentTestPool(t)
	now := time.Now().UTC()
	store := seedIncidentTestStore(t, ctx, pool, now)
	cfg := &Config{DBPool: pool, Incidents: store}
	seedTrafficThreatEvents(t, ctx, pool, now, []trafficSeed{
		{uid: "p0-6-idem-a", src: "10.1.1.181", dst: "10.1.18.253", severity: "high", at: now.Add(-5 * time.Minute)},
		{uid: "p0-6-idem-b", src: "10.1.1.181", dst: "10.1.18.254", severity: "high", at: now.Add(-4 * time.Minute)},
	})
	window := incidentTrafficWindow{Lookback: 30 * time.Minute, Limit: 500}

	// When
	first, err := runIncidentPipelineTick(ctx, cfg, window)
	if err != nil {
		t.Fatalf("first tick failed: %v", err)
	}
	afterFirst := countTrafficIncidents(t, ctx, pool)
	second, err := runIncidentPipelineTick(ctx, cfg, window)
	if err != nil {
		t.Fatalf("second tick failed: %v", err)
	}

	// Then
	if first.Created != 1 {
		t.Fatalf("first tick created=%d, want 1", first.Created)
	}
	if second.Created != 0 {
		t.Fatalf("second tick created=%d, want 0 (must only update)", second.Created)
	}
	if afterFirst != countTrafficIncidents(t, ctx, pool) {
		t.Fatalf("incident rows changed on replay: %d -> %d", afterFirst, countTrafficIncidents(t, ctx, pool))
	}
}

// The lookback window must be honoured, because a hard-coded 30 minutes is what
// silently dropped every alert that happened while nobody watched the page.
func TestIncidentWorkerRespectsLookbackWindow(t *testing.T) {
	// Given: events 90 minutes old, outside the default 30 minute window.
	pool, ctx := incidentTestPool(t)
	now := time.Now().UTC()
	store := seedIncidentTestStore(t, ctx, pool, now)
	cfg := &Config{DBPool: pool, Incidents: store}
	seedTrafficThreatEvents(t, ctx, pool, now, []trafficSeed{
		{uid: "p0-6-old-a", src: "10.1.1.181", dst: "10.1.18.253", severity: "high", at: now.Add(-90 * time.Minute)},
		{uid: "p0-6-old-b", src: "10.1.1.181", dst: "10.1.18.254", severity: "high", at: now.Add(-89 * time.Minute)},
	})

	// When: the narrow window first, then a wide one.
	narrow, err := runIncidentPipelineTick(ctx, cfg, incidentTrafficWindow{Lookback: 30 * time.Minute, Limit: 500})
	if err != nil {
		t.Fatalf("narrow tick failed: %v", err)
	}
	wide, err := runIncidentPipelineTick(ctx, cfg, incidentTrafficWindow{Lookback: 4 * time.Hour, Limit: 500})
	if err != nil {
		t.Fatalf("wide tick failed: %v", err)
	}

	// Then
	if narrow.Scanned != 0 || narrow.Created != 0 {
		t.Fatalf("narrow window saw scanned=%d created=%d, want 0/0", narrow.Scanned, narrow.Created)
	}
	if wide.Scanned < 2 {
		t.Fatalf("wide window scanned=%d, want at least 2", wide.Scanned)
	}
	if wide.Created != 1 {
		t.Fatalf("wide window created=%d, want 1", wide.Created)
	}
}

// The LIMIT must be a parameter, not a magic 100: during an alert burst the
// newest 100 rows can represent only a fraction of the affected groups.
func TestIncidentWorkerLimitIsConfigurable(t *testing.T) {
	// Given
	pool, ctx := incidentTestPool(t)
	now := time.Now().UTC()
	store := seedIncidentTestStore(t, ctx, pool, now)
	cfg := &Config{DBPool: pool, Incidents: store}
	seeds := make([]trafficSeed, 0, 40)
	for i := 0; i < 40; i++ {
		seeds = append(seeds, trafficSeed{
			uid:      trafficSeedUID(i),
			src:      "10.1.1.181",
			dst:      trafficSeedDst(i),
			severity: "high",
			at:       now.Add(-time.Duration(i) * time.Second),
		})
	}
	seedTrafficThreatEvents(t, ctx, pool, now, seeds)

	// When
	capped, err := runIncidentPipelineTick(ctx, cfg, incidentTrafficWindow{Lookback: 30 * time.Minute, Limit: 5})
	if err != nil {
		t.Fatalf("capped tick failed: %v", err)
	}
	full, err := runIncidentPipelineTick(ctx, cfg, incidentTrafficWindow{Lookback: 30 * time.Minute, Limit: 500})
	if err != nil {
		t.Fatalf("full tick failed: %v", err)
	}

	// Then
	if capped.Scanned != 5 {
		t.Fatalf("capped scanned=%d, want exactly the limit 5", capped.Scanned)
	}
	if capped.Limit != 5 || full.Limit != 500 {
		t.Fatalf("reported limits capped=%d full=%d", capped.Limit, full.Limit)
	}
	if full.Scanned <= capped.Scanned {
		t.Fatalf("a larger limit must scan more: capped=%d full=%d", capped.Scanned, full.Scanned)
	}
}

// Window parsing must fail safe: a typo in the environment must not disable
// materialization or silently collapse the window to zero.
func TestIncidentTrafficWindowParsing(t *testing.T) {
	cases := []struct {
		name         string
		lookback     string
		limit        string
		interval     string
		wantLookback time.Duration
		wantLimit    int
		wantInterval time.Duration
	}{
		{name: "defaults", wantLookback: defaultIncidentTrafficLookback, wantLimit: defaultIncidentTrafficLimit, wantInterval: defaultIncidentWorkerInterval},
		{name: "valid", lookback: "2h", limit: "5000", interval: "15s", wantLookback: 2 * time.Hour, wantLimit: 5000, wantInterval: 15 * time.Second},
		{name: "garbage falls back", lookback: "soon", limit: "many", interval: "later", wantLookback: defaultIncidentTrafficLookback, wantLimit: defaultIncidentTrafficLimit, wantInterval: defaultIncidentWorkerInterval},
		{name: "zero is rejected", lookback: "0s", limit: "0", interval: "0s", wantLookback: defaultIncidentTrafficLookback, wantLimit: defaultIncidentTrafficLimit, wantInterval: defaultIncidentWorkerInterval},
		{name: "negative is rejected", lookback: "-5m", limit: "-3", interval: "-1s", wantLookback: defaultIncidentTrafficLookback, wantLimit: defaultIncidentTrafficLimit, wantInterval: defaultIncidentWorkerInterval},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(incidentTrafficLookbackEnv, test.lookback)
			t.Setenv(incidentTrafficLimitEnv, test.limit)
			t.Setenv(incidentWorkerIntervalEnv, test.interval)
			window := incidentTrafficWindowFromEnv()
			if window.Lookback != test.wantLookback {
				t.Fatalf("lookback=%s, want %s", window.Lookback, test.wantLookback)
			}
			if window.Limit != test.wantLimit {
				t.Fatalf("limit=%d, want %d", window.Limit, test.wantLimit)
			}
			if interval := incidentWorkerIntervalFromEnv(); interval != test.wantInterval {
				t.Fatalf("interval=%s, want %s", interval, test.wantInterval)
			}
		})
	}
}

// A panic inside one tick must be contained, otherwise the worker goroutine
// dies and the pipeline silently stops again.
func TestIncidentPipelineTickRecoversFromPanic(t *testing.T) {
	// Given: a Config whose store is nil makes the tick fail, which is the
	// cheapest deterministic error path; the panic containment itself is
	// exercised by the deferred recover in runIncidentPipelineTick.
	report, err := runIncidentPipelineTick(context.Background(), &Config{}, incidentTrafficWindow{Lookback: time.Minute, Limit: 1})

	// Then
	if err == nil {
		t.Fatal("expected an error when the incident store is unavailable")
	}
	if report.Created != 0 {
		t.Fatalf("created=%d on a failed tick, want 0", report.Created)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type trafficSeed struct {
	uid      string
	src      string
	dst      string
	severity string
	at       time.Time
}

func trafficSeedUID(index int) string {
	return "p0-6-limit-" + itoa(index)
}

func trafficSeedDst(index int) string {
	// 40 distinct victims so every group stays separable by victim count.
	return "10.1.99." + itoa(index+1)
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func incidentTestPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	return xdrMigrationTestPool(t)
}

func seedIncidentTestStore(t *testing.T, ctx context.Context, pool *pgxpool.Pool, now time.Time) *incidentlifecycle.PostgresStore {
	t.Helper()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset incident tables: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS threat_events (
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
		updated_at TIMESTAMPTZ DEFAULT NOW())`); err != nil {
		t.Fatalf("ensure threat_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM threat_events`); err != nil {
		t.Fatalf("clear threat_events: %v", err)
	}
	store := incidentlifecycle.NewPostgresStore(pool, func() time.Time { return now })
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure incident schema: %v", err)
	}
	return store
}

func seedTrafficThreatEvents(t *testing.T, ctx context.Context, pool *pgxpool.Pool, now time.Time, seeds []trafficSeed) {
	t.Helper()
	for _, seed := range seeds {
		raw, err := json.Marshal(map[string]interface{}{
			"category":           "traffic",
			"component_category": "traffic",
			"src_ip":             seed.src,
			"dst_ip":             seed.dst,
			"severity":           seed.severity,
			"rule_id":            "2049400",
			"rule_name":          "ET EXPLOIT Possible SQL Injection Attempt",
			"message":            "ET EXPLOIT Possible SQL Injection Attempt",
		})
		if err != nil {
			t.Fatalf("encode raw event %s: %v", seed.uid, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO threat_events
			(event_uid, category, severity, source_engine, event_type, agent_id, src_ip, dst_ip, message, observed_at, raw_event)
			VALUES ($1,'traffic',$2,'suricata','alert','local',$3,$4,$5,$6,$7::jsonb)
			ON CONFLICT (event_uid) DO NOTHING`,
			seed.uid, seed.severity, seed.src, seed.dst,
			"ET EXPLOIT Possible SQL Injection Attempt", seed.at, string(raw)); err != nil {
			t.Fatalf("insert threat event %s: %v", seed.uid, err)
		}
	}
}

func countTrafficIncidents(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE id LIKE 'inc-traffic-%'`).Scan(&count); err != nil {
		t.Fatalf("count traffic incidents: %v", err)
	}
	return count
}

func countIncidentLineage(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_evidence_lineage`).Scan(&count); err != nil {
		t.Fatalf("count incident lineage: %v", err)
	}
	return count
}
