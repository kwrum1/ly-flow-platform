package ingestionauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentidentity"
)

func TestHTTPPrincipalAuthenticatesAndBindsImmutableAgentID(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	authenticator, audit := newTestAuthenticator(t, now, 10)
	request := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	request.Header.Set(AgentIDHeader, "agent-1")
	request.Header.Set("Authorization", "Bearer legacy-secret")

	// When
	principal, err := authenticator.HTTPPrincipal(request, "traffic")

	// Then
	if err != nil {
		t.Fatalf("authenticate principal: %v", err)
	}
	if principal.AgentID() != "agent-1" {
		t.Fatalf("principal agent id = %q", principal.AgentID())
	}
	if _, err := principal.BindPayloadAgentID("agent-2"); err == nil {
		t.Fatal("conflicting payload identity was accepted")
	}
	if bound, err := principal.BindPayloadAgentID(""); err != nil || bound != "agent-1" {
		t.Fatalf("blank payload binding = %q, %v", bound, err)
	}
	if got := audit.Events(); len(got) != 1 || got[0].Outcome != OutcomeAuthenticated {
		t.Fatalf("audit events = %#v", got)
	}
}

func TestHTTPPrincipalRejectsMissingCredentialsAndRateLimit(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	authenticator, audit := newTestAuthenticator(t, now, 1)
	missing := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	valid := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	valid.Header.Set(AgentIDHeader, "agent-1")
	valid.Header.Set("Authorization", "Bearer legacy-secret")

	// When
	_, missingErr := authenticator.HTTPPrincipal(missing, "runtime")
	_, firstErr := authenticator.HTTPPrincipal(valid, "runtime")
	_, limitedErr := authenticator.HTTPPrincipal(valid, "runtime")

	// Then
	if !IsUnauthorized(missingErr) {
		t.Fatalf("missing credentials error = %v", missingErr)
	}
	if firstErr != nil {
		t.Fatalf("first request error = %v", firstErr)
	}
	if !IsRateLimited(limitedErr) {
		t.Fatalf("rate-limit error = %v", limitedErr)
	}
	if got := audit.Events(); len(got) != 3 || got[2].Outcome != OutcomeRateLimited {
		t.Fatalf("audit events = %#v", got)
	}
}

func TestHTTPPrincipalHonorsMigrationOverlapAndRetirement(t *testing.T) {
	// Given
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
	if err := manager.Transition(id, agentidentity.StateLegacyVerified, 1); err != nil {
		t.Fatalf("legacy verified: %v", err)
	}
	if err := manager.Transition(id, agentidentity.StateHashMigrated, 2); err != nil {
		t.Fatalf("hash migrated: %v", err)
	}
	if err := manager.BeginRotation(id, "new-secret", time.Hour, 3); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}
	authenticator := New(manager, NewMemoryAudit(), func() time.Time { return now }, 10, time.Minute)

	// When
	legacyErr := authenticateHTTPCredential(authenticator, "legacy-secret")
	newErr := authenticateHTTPCredential(authenticator, "new-secret")
	retireErr := manager.RetireLegacy(id, 5)
	legacyAfterRetirementErr := authenticateHTTPCredential(authenticator, "legacy-secret")
	newAfterRetirementErr := authenticateHTTPCredential(authenticator, "new-secret")

	// Then
	if legacyErr != nil || newErr != nil || retireErr != nil || newAfterRetirementErr != nil {
		t.Fatalf("migration errors = legacy:%v new:%v retire:%v new-after:%v", legacyErr, newErr, retireErr, newAfterRetirementErr)
	}
	if !IsUnauthorized(legacyAfterRetirementErr) {
		t.Fatalf("legacy after retirement error = %v", legacyAfterRetirementErr)
	}
}

func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	// Given
	request := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(`{"data":"`+strings.Repeat("x", int(MaxBodyBytes))+`"}`))
	recorder := httptest.NewRecorder()
	var payload map[string]string

	// When
	err := DecodeJSON(recorder, request, &payload)

	// Then
	if !IsBodyTooLarge(err) {
		t.Fatalf("oversized body error = %v", err)
	}
}

func newTestAuthenticator(t *testing.T, now time.Time, limit int) (*Authenticator, *MemoryAudit) {
	t.Helper()
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "legacy-secret", agentidentity.EnabledTransports{HTTP: true, GRPC: true})
	if err != nil {
		t.Fatalf("legacy record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	audit := NewMemoryAudit()
	return New(manager, audit, func() time.Time { return now }, limit, time.Minute), audit
}

func authenticateHTTPCredential(authenticator *Authenticator, credential string) error {
	request := httptest.NewRequest(http.MethodPost, "/ingest", nil)
	request.Header.Set(AgentIDHeader, "agent-1")
	request.Header.Set("Authorization", "Bearer "+credential)
	_, err := authenticator.HTTPPrincipal(request, "traffic")
	return err
}
