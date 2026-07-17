package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentidentity"
	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
)

type failingOutcomeAudit struct{ outcome string }

func (a failingOutcomeAudit) Record(_ context.Context, event ingestionauth.Event) error {
	if event.Outcome == a.outcome {
		return errors.New("audit persistence failed")
	}
	return nil
}

type recordingIngestionWriter struct{ calls int }

func (w *recordingIngestionWriter) Write(context.Context, string, map[string]interface{}) error {
	w.calls++
	return nil
}

func TestTaskResultUsesAuthenticatedPrincipalAndRejectsPayloadMismatch(t *testing.T) {
	// Given
	cfg, audit := ingestionTestConfig(t, 10)
	matching := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/task-result", `{"agent_id":"agent-1","task_id":"task-1","status":"ok"}`)
	mismatch := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/task-result", `{"agent_id":"agent-2","task_id":"task-1","status":"ok"}`)

	// When
	matchingRecorder := httptest.NewRecorder()
	agentTaskResultHandler(cfg).ServeHTTP(matchingRecorder, matching)
	mismatchRecorder := httptest.NewRecorder()
	agentTaskResultHandler(cfg).ServeHTTP(mismatchRecorder, mismatch)

	// Then
	if matchingRecorder.Code != http.StatusOK {
		t.Fatalf("matching status = %d body = %s", matchingRecorder.Code, matchingRecorder.Body.String())
	}
	if mismatchRecorder.Code != http.StatusForbidden {
		t.Fatalf("mismatch status = %d body = %s", mismatchRecorder.Code, mismatchRecorder.Body.String())
	}
	events := audit.Events()
	if len(events) < 4 || events[len(events)-1].Outcome != ingestionauth.OutcomeIdentityMismatch {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestRuntimeIngestionRejectsUnauthenticatedOversizedAndExcessiveRequests(t *testing.T) {
	// Given
	cfg, audit := ingestionTestConfig(t, 1)
	unauthenticated := httptest.NewRequest(http.MethodPost, "/api/v1/agent/runtime-event", strings.NewReader(`{"type":"runtime.process"}`))
	valid := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"agent_id":"agent-1","type":"runtime.process"}`)
	excessive := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"agent_id":"agent-1","type":"runtime.process"}`)

	// When
	unauthenticatedRecorder := httptest.NewRecorder()
	agentRuntimeEventHandler(cfg).ServeHTTP(unauthenticatedRecorder, unauthenticated)
	validRecorder := httptest.NewRecorder()
	agentRuntimeEventHandler(cfg).ServeHTTP(validRecorder, valid)
	limitedRecorder := httptest.NewRecorder()
	agentRuntimeEventHandler(cfg).ServeHTTP(limitedRecorder, excessive)

	// Then
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticatedRecorder.Code)
	}
	if limitedRecorder.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status = %d body = %s", limitedRecorder.Code, limitedRecorder.Body.String())
	}
	events := audit.Events()
	if len(events) == 0 || events[len(events)-1].Outcome != ingestionauth.OutcomeRateLimited {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestRuntimeIngestionRejectsOversizedBody(t *testing.T) {
	// Given
	cfg, audit := ingestionTestConfig(t, 10)
	request := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"data":"`+strings.Repeat("x", int(ingestionauth.MaxBodyBytes))+`"}`)

	// When
	recorder := httptest.NewRecorder()
	agentRuntimeEventHandler(cfg).ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	events := audit.Events()
	if len(events) != 2 || events[1].Outcome != ingestionauth.OutcomeRejected {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestRuntimeIngestionRejectsMalformedJSONAndAudits(t *testing.T) {
	// Given
	cfg, audit := ingestionTestConfig(t, 10)
	request := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"agent_id":`)

	// When
	recorder := httptest.NewRecorder()
	agentRuntimeEventHandler(cfg).ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	events := audit.Events()
	if len(events) != 2 || events[1].Outcome != ingestionauth.OutcomeRejected {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestComponentAndRASPPayloadIdentityCannotOverridePrincipal(t *testing.T) {
	// Given
	cfg, audit := ingestionTestConfig(t, 10)
	component := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/component-alert", `{"schema_version":"lyflow.component_alert.v1","id":"alert-1","category":"network","source_engine":"suricata","rule_id":"r1","rule_name":"rule","severity":"low","score_hint":10,"occurred_at":"2026-07-12T00:00:00Z","source":"sensor","summary":"inert","entities":{"agent_id":"agent-2"}}`)
	rasp := authenticatedIngestionRequest(http.MethodPost, "/api/v1/rasp/event", `{"agent_id":"agent-2","attack_type":"inert.test"}`)

	// When
	componentRecorder := httptest.NewRecorder()
	agentComponentAlertHandler(cfg).ServeHTTP(componentRecorder, component)
	raspRecorder := httptest.NewRecorder()
	raspReceiveEventHandler(cfg).ServeHTTP(raspRecorder, rasp)

	// Then
	if componentRecorder.Code != http.StatusForbidden || raspRecorder.Code != http.StatusForbidden {
		t.Fatalf("mismatch statuses = component:%d rasp:%d", componentRecorder.Code, raspRecorder.Code)
	}
	if got := audit.Events(); len(got) < 4 {
		t.Fatalf("missing lifecycle audit events: %#v", got)
	}
}

func TestHTTPRejectionAuditFailureSurfacesWithoutCredentialLeak(t *testing.T) {
	tests := []struct {
		name    string
		outcome string
		limit   int
		prime   bool
		request func() *http.Request
		handler func(*Config) http.Handler
	}{
		{name: "malformed", outcome: ingestionauth.OutcomeRejected, limit: 10, request: func() *http.Request {
			return authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"agent_id":`)
		}, handler: func(cfg *Config) http.Handler { return agentRuntimeEventHandler(cfg) }},
		{name: "oversized", outcome: ingestionauth.OutcomeRejected, limit: 10, request: func() *http.Request {
			return authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"data":"`+strings.Repeat("x", int(ingestionauth.MaxBodyBytes))+`"}`)
		}, handler: func(cfg *Config) http.Handler { return agentRuntimeEventHandler(cfg) }},
		{name: "mismatch", outcome: ingestionauth.OutcomeIdentityMismatch, limit: 10, request: func() *http.Request {
			return authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/task-result", `{"agent_id":"agent-2","task_id":"task-1"}`)
		}, handler: func(cfg *Config) http.Handler { return agentTaskResultHandler(cfg) }},
		{name: "rate-limit", outcome: ingestionauth.OutcomeRateLimited, limit: 1, prime: true, request: func() *http.Request {
			return authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/runtime-event", `{"agent_id":"agent-1"}`)
		}, handler: func(cfg *Config) http.Handler { return agentRuntimeEventHandler(cfg) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			cfg := ingestionConfigWithAudit(t, test.limit, failingOutcomeAudit{outcome: test.outcome})
			if test.prime {
				_, err := cfg.IngestionAuth.HTTPPrincipal(authenticatedIngestionRequest(http.MethodPost, "/prime", `{}`), "http.runtime-event")
				if err != nil {
					t.Fatalf("prime limiter: %v", err)
				}
			}

			// When
			recorder := httptest.NewRecorder()
			test.handler(cfg).ServeHTTP(recorder, test.request())

			// Then
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "legacy-secret") {
				t.Fatal("credential leaked in audit failure response")
			}
		})
	}
}

func TestHTTPAcceptanceAuditFailurePreventsIngestionMutation(t *testing.T) {
	// Given
	cfg := ingestionConfigWithAudit(t, 10, failingOutcomeAudit{outcome: ingestionauth.OutcomeAccepted})
	writer := &recordingIngestionWriter{}
	cfg.IngestionWriter = writer
	request := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/traffic-event", `{"agent_id":"agent-1","stream":"flows:raw","data":"{}"}`)

	// When
	recorder := httptest.NewRecorder()
	agentTrafficEventHandler(cfg).ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if writer.calls != 0 {
		t.Fatalf("ingestion writes = %d, want zero", writer.calls)
	}
}

func ingestionTestConfig(t *testing.T, limit int) (*Config, *ingestionauth.MemoryAudit) {
	t.Helper()
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "legacy-secret", agentidentity.EnabledTransports{HTTP: true})
	if err != nil {
		t.Fatalf("legacy record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	audit := ingestionauth.NewMemoryAudit()
	authenticator := ingestionauth.New(manager, audit, func() time.Time { return now }, limit, time.Minute)
	return &Config{AgentIdentity: manager, IngestionAuth: authenticator}, audit
}

func ingestionConfigWithAudit(t *testing.T, limit int, audit ingestionauth.Audit) *Config {
	t.Helper()
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "legacy-secret", agentidentity.EnabledTransports{HTTP: true})
	if err != nil {
		t.Fatalf("legacy record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	return &Config{AgentIdentity: manager, IngestionAuth: ingestionauth.New(manager, audit, func() time.Time { return now }, limit, time.Minute)}
}

func authenticatedIngestionRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set(ingestionauth.AgentIDHeader, "agent-1")
	request.Header.Set("Authorization", "Bearer legacy-secret")
	return request
}
