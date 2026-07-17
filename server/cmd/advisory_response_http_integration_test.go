package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/advisoryresponse"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

type advisoryHTTPRequest struct {
	method string
	path   string
	body   string
	userID int64
	role   auth.UserRole
}

func TestAdvisoryResponseHTTP_rejects_shadow_and_unsupported_at_boundary(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		action    advisoryresponse.Action
		errorCode string
	}{
		{name: "shadow", algorithm: "v3-shadow", action: advisoryresponse.ActionIncreaseMonitoring, errorCode: "active_input_required"},
		{name: "unsupported", algorithm: advisoryresponse.ActiveAlgorithm, action: advisoryresponse.Action("file_delete"), errorCode: "unsupported_action"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			candidateID := advisoryresponse.CandidateID("inc-http", test.action, "agent-http")
			body := fmt.Sprintf(`{"candidate_id":%q,"incident_id":"inc-http","agent_id":"agent-http","algorithm":%q,"action":%q,"target":"agent-http","reason":"boundary","idempotency_key":"boundary"}`, candidateID, test.algorithm, test.action)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/response/advisories", strings.NewReader(body))
			response := httptest.NewRecorder()

			// When
			advisoryResponseHandler(&Config{AdvisoryResponses: &advisoryresponse.PostgresStore{}}).ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), test.errorCode) {
				t.Fatalf("boundary status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAdvisoryResponseHTTP_rejects_shadow_and_missing_verification(t *testing.T) {
	// Given
	pool, ctx := xdrMigrationTestPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS response_advisory_audit, response_advisories, incident_lifecycle_cutover_audit, incident_lifecycle_legacy_snapshots, incident_lifecycle_audit, incident_evidence_lineage, incident_suppressions, incidents, incident_lifecycle_schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset advisory HTTP tables: %v", err)
	}
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	incidents := incidentlifecycle.NewPostgresStore(pool, func() time.Time { return now })
	if err := incidents.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure incident schema: %v", err)
	}
	snapshot, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, []incidentlifecycle.Candidate{{IncidentID: "inc-http", SourceChainID: "chain-http", Severity: "high", FirstSeen: now.Add(-time.Hour), LastSeen: now}})
	if err != nil {
		t.Fatalf("create incident snapshot: %v", err)
	}
	if _, err := incidents.SyncActive(ctx, snapshot); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS agents (uuid TEXT PRIMARY KEY, status TEXT, last_heartbeat TIMESTAMPTZ)`); err != nil {
		t.Fatalf("create Agent table: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE agents ADD COLUMN IF NOT EXISTS status TEXT, ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ`); err != nil {
		t.Fatalf("ensure Agent health columns: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agents(uuid,status,last_heartbeat) VALUES ('agent-http','online',$1) ON CONFLICT (uuid) DO UPDATE SET status='online',last_heartbeat=$1`, now); err != nil {
		t.Fatalf("seed Agent: %v", err)
	}
	store := advisoryresponse.NewPostgresStore(pool, func() time.Time { return now }, advisoryresponse.DefaultLimits())
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure advisory schema: %v", err)
	}
	config := &Config{AdvisoryResponses: store}
	serve := func(input advisoryHTTPRequest) *httptest.ResponseRecorder {
		request := httptest.NewRequest(input.method, input.path, strings.NewReader(input.body))
		request = request.WithContext(context.WithValue(request.Context(), auth.UserContextKey, input.userID))
		request = request.WithContext(context.WithValue(request.Context(), auth.RoleContextKey, input.role))
		response := httptest.NewRecorder()
		advisoryResponseHandler(config).ServeHTTP(response, request)
		return response
	}
	shadowBody := `{"candidate_id":"shadow-http","incident_id":"inc-http","agent_id":"agent-http","algorithm":"v3-shadow","action":"increase_monitoring","target":"agent-http","reason":"shadow","idempotency_key":"submit-shadow"}`
	activeID := advisoryresponse.CandidateID("inc-http", advisoryresponse.ActionIncreaseMonitoring, "agent-http")
	activeBody := fmt.Sprintf(`{"candidate_id":%q,"incident_id":"inc-http","agent_id":"agent-http","algorithm":"v2-active","action":"increase_monitoring","target":"agent-http","reason":"active","idempotency_key":"submit-active"}`, activeID)

	// When
	shadow := serve(advisoryHTTPRequest{method: http.MethodPost, path: "/api/v1/response/advisories", body: shadowBody, userID: 7, role: auth.RoleAnalyst})
	created := serve(advisoryHTTPRequest{method: http.MethodPost, path: "/api/v1/response/advisories", body: activeBody, userID: 7, role: auth.RoleAnalyst})
	approved := serve(advisoryHTTPRequest{method: http.MethodPost, path: "/api/v1/response/advisories/" + activeID + "/approve", body: `{"idempotency_key":"approve-active"}`, userID: 8, role: auth.RoleAdmin})

	// Then
	if shadow.Code != http.StatusBadRequest {
		t.Fatalf("shadow status=%d body=%s", shadow.Code, shadow.Body.String())
	}
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	if approved.Code != http.StatusConflict || !strings.Contains(approved.Body.String(), "verification_required") {
		t.Fatalf("unverified approval status=%d body=%s", approved.Code, approved.Body.String())
	}
}
