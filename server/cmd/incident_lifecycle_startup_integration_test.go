package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

func TestInitializeIncidentLifecycleRuntime_migrates_live_legacy_map_and_is_restart_idempotent(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset incident lifecycle tables: %v", err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	graph, err := newXDRGraphRuntime(ctx, pool, newXDRCanonicalAdapter(func() time.Time { return now }, now.Add(time.Hour)))
	if err != nil {
		t.Fatalf("create XDR graph runtime: %v", err)
	}
	input := fixtureXDRInput{records: [][]byte{
		marshalXDRFixture(t, legacyCutoverEvent(t, "startup-initial", "initial_access", now.Add(-time.Minute))),
		marshalXDRFixture(t, legacyCutoverEvent(t, "startup-execution", "execution", now)),
	}}
	config := &Config{DBPool: pool, XDRGraph: graph, XDRInput: input}
	active, err := xdrActiveChainsResponse(ctx, config, 100)
	if err != nil {
		t.Fatalf("derive legacy active chain: %v", err)
	}
	chains := active.activeChains()
	if len(chains) == 0 {
		t.Fatal("legacy production path produced no active chain")
	}
	incidentID := "inc-" + strings.TrimPrefix(chains[0].ID, "chain-")
	legacyRequest := httptest.NewRequest(http.MethodPut, "/api/v1/incidents/"+incidentID+"/status", strings.NewReader(`{"status":"processing"}`))
	legacyResponse := httptest.NewRecorder()
	incidentDetailHandler(config).ServeHTTP(legacyResponse, legacyRequest)
	if legacyResponse.Code != http.StatusOK {
		t.Fatalf("legacy production status writer=%d body=%s", legacyResponse.Code, legacyResponse.Body.String())
	}
	checkpointStore := incidentlifecycle.NewPostgresStore(pool, func() time.Time { return now })
	if err := checkpointStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure checkpoint schema: %v", err)
	}
	checkpointConfig := &Config{IncidentCheckpoint: checkpointStore, IncidentSnapshot: &incidentSnapshotState{}}
	if _, err := checkpointLegacyIncidentStatuses(ctx, checkpointConfig); err != nil {
		t.Fatalf("checkpoint live legacy status: %v", err)
	}
	clearLegacyIncidentStatuses()

	// When
	if err := initializeIncidentLifecycleRuntime(ctx, config); err != nil {
		t.Fatalf("initialize incident lifecycle: %v", err)
	}
	firstReport := config.IncidentSnapshot.report
	connectionString := pool.Config().ConnString()
	pool.Close()
	restartPool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatalf("restart PostgreSQL connection: %v", err)
	}
	t.Cleanup(restartPool.Close)
	restarted := &Config{DBPool: restartPool}
	if err := initializeIncidentLifecycleRuntime(ctx, restarted); err != nil {
		t.Fatalf("restart incident lifecycle: %v", err)
	}

	// Then
	incident, err := restarted.Incidents.Get(ctx, incidentID)
	if err != nil {
		t.Fatalf("load migrated incident: %v", err)
	}
	if incident.Status != incidentlifecycle.StatusProcessing {
		t.Fatalf("migrated status=%s, want processing", incident.Status)
	}
	if len(incident.Evidence) != 2 {
		t.Fatalf("migrated evidence=%d, want 2", len(incident.Evidence))
	}
	if incident.Assignee != "" || incident.Suppressed {
		t.Fatalf("legacy-only unavailable fields were fabricated: assignee=%q suppressed=%v", incident.Assignee, incident.Suppressed)
	}
	if firstReport.SnapshotChecksum == "" || firstReport.SnapshotCapturedAt.IsZero() {
		t.Fatalf("durable snapshot metadata missing: %+v", firstReport)
	}
	if firstReport.Captured != 1 || firstReport.Imported != 1 || firstReport.Recovered.Status != 1 || firstReport.Recovered.Evidence != 2 {
		t.Fatalf("startup snapshot recovery report=%+v", firstReport)
	}
	if firstReport.Unrecoverable.Assignee != 1 || firstReport.Unrecoverable.Suppression != 1 || firstReport.Unrecoverable.Evidence != 0 || firstReport.Unrecoverable.TransitionHistory != 1 || !firstReport.CutoverMarked {
		t.Fatalf("startup snapshot unrecoverable report=%+v", firstReport)
	}
	if restarted.IncidentSnapshot.report.Imported != firstReport.Imported || !restarted.IncidentSnapshot.report.CutoverMarked {
		t.Fatalf("restart did not restore durable cutover report=%+v", restarted.IncidentSnapshot.report)
	}
	var auditCount int
	if err := restartPool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE action=$1 AND incident_id=$2`, incidentlifecycle.ActionSnapshot, incidentID).Scan(&auditCount); err != nil {
		t.Fatalf("count startup snapshot audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("startup snapshot audit rows=%d, want 1", auditCount)
	}
	var cutoverCount int
	if err := restartPool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_cutover_audit WHERE name='todo19-legacy-incident-status'`).Scan(&cutoverCount); err != nil {
		t.Fatalf("count startup cutover audit: %v", err)
	}
	if cutoverCount != 1 {
		t.Fatalf("startup cutover audit rows=%d, want 1", cutoverCount)
	}
}

func TestInitializeIncidentLifecycleRuntime_refuses_empty_new_process_without_durable_snapshot(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset incident lifecycle tables: %v", err)
	}
	clearLegacyIncidentStatuses()
	config := &Config{DBPool: pool}

	// When
	err := initializeIncidentLifecycleRuntime(ctx, config)

	// Then
	if !errors.Is(err, incidentlifecycle.ErrLegacySnapshotRequired) {
		t.Fatalf("startup error=%v, want durable snapshot required", err)
	}
	var cutoverCount int
	if queryErr := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_cutover_audit WHERE name=$1`, incidentlifecycle.LegacyCutoverName).Scan(&cutoverCount); queryErr != nil {
		t.Fatalf("count cutover markers: %v", queryErr)
	}
	if cutoverCount != 0 {
		t.Fatalf("empty startup marked cutover rows=%d", cutoverCount)
	}
}

func legacyCutoverEvent(t *testing.T, id, stage string, now time.Time) contracts.CanonicalSecurityEvent {
	t.Helper()
	event := canonicalXDRTestEvent(t, id, now)
	payload, err := json.Marshal(map[string]string{"hostname": "legacy-host", "stage_hint": stage})
	if err != nil {
		t.Fatalf("encode legacy cutover event: %v", err)
	}
	digest := sha256.Sum256(payload)
	event.Payload = payload
	event.Provenance.PayloadSHA256 = hex.EncodeToString(digest[:])
	event.Governance.RedactedFields = nil
	return event
}
