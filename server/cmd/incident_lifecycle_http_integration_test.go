package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func TestIncidentMutationHTTP_binds_caller_key_to_the_complete_payload(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset incident lifecycle tables: %v", err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	store := incidentlifecycle.NewPostgresStore(pool, func() time.Time { return now })
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure incident schema: %v", err)
	}
	snapshot, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, []incidentlifecycle.Candidate{{
		IncidentID: "inc-http", SourceChainID: "chain-http", Severity: "high", FirstSeen: now.Add(-time.Hour), LastSeen: now,
	}})
	if err != nil {
		t.Fatalf("create active snapshot: %v", err)
	}
	if _, err := store.SyncActive(ctx, snapshot); err != nil {
		t.Fatalf("seed HTTP incident: %v", err)
	}
	handler := incidentMutationHandler(&Config{Incidents: store}, "inc-http", "status")
	serve := func(reason string) *httptest.ResponseRecorder {
		body := `{"status":"triaged","reason":"` + reason + `","expected_version":1,"idempotency_key":"caller-http-key"}`
		request := httptest.NewRequest(http.MethodPut, "/api/v1/incidents/inc-http/status", strings.NewReader(body))
		request = request.WithContext(context.WithValue(request.Context(), auth.UserContextKey, int64(7)))
		request = request.WithContext(context.WithValue(request.Context(), auth.RoleContextKey, auth.RoleAnalyst))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	// When
	first := serve("first review")
	replay := serve("first review")
	conflict := serve("different review")

	// Then
	if first.Code != http.StatusOK || replay.Code != http.StatusOK || conflict.Code != http.StatusConflict {
		t.Fatalf("HTTP idempotency statuses first=%d replay=%d conflict=%d", first.Code, replay.Code, conflict.Code)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE idempotency_key='caller-http-key'`).Scan(&auditCount); err != nil {
		t.Fatalf("count caller-key audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("caller-key audit rows=%d, want 1", auditCount)
	}
}
