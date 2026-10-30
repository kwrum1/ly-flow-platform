package ingestv2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func tenantHandler(writer *fakeWriter) Handler {
	return Handler{
		Auth:   func(*http.Request, string) (string, error) { return "agent-1", nil },
		Writer: writer,
	}
}

func TestIngestOverwritesClientTenant(t *testing.T) {
	writer := &fakeWriter{}
	handler := tenantHandler(writer)

	event := testEvent()
	event.TenantID = "evil-tenant"

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if writer.events[0].TenantID != "default" {
		t.Fatalf("tenant=%q, client-supplied tenant must be overwritten", writer.events[0].TenantID)
	}
}

func TestIngestUsesConfiguredTenant(t *testing.T) {
	writer := &fakeWriter{}
	handler := tenantHandler(writer)
	handler.TenantID = "acme"

	event := testEvent()
	event.TenantID = "other"

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, event))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if writer.events[0].TenantID != "acme" {
		t.Fatalf("tenant=%q, want configured tenant", writer.events[0].TenantID)
	}
}

func TestIngestUsesResolvedTenant(t *testing.T) {
	writer := &fakeWriter{}
	handler := tenantHandler(writer)
	handler.Tenant = func(_ *http.Request, principal string) (string, error) {
		if principal != "agent-1" {
			t.Fatalf("principal=%q", principal)
		}
		return "beta", nil
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, testEvent()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if writer.events[0].TenantID != "beta" {
		t.Fatalf("tenant=%q, want resolved tenant", writer.events[0].TenantID)
	}
}

func TestIngestRejectsWhenTenantCannotBeResolved(t *testing.T) {
	writer := &fakeWriter{}
	handler := tenantHandler(writer)
	handler.Tenant = func(*http.Request, string) (string, error) {
		return "", errors.New("no tenant mapping")
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, testEvent()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", recorder.Code)
	}
	if len(writer.events) != 0 {
		t.Fatal("event must not be written when tenant resolution fails")
	}
}

func TestIngestTenantBindingAppliesToEveryEvent(t *testing.T) {
	writer := &fakeWriter{}
	handler := tenantHandler(writer)

	first := testEvent()
	first.EventUID = "evt-1"
	first.TenantID = "a"
	second := testEvent()
	second.EventUID = "evt-2"
	second.TenantID = "b"

	request := httptest.NewRequest(http.MethodPost, "/api/v2/ingest/events", requestBody(t, first, second))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, event := range writer.events {
		if event.TenantID != "default" {
			t.Fatalf("event %s tenant=%q", event.EventUID, event.TenantID)
		}
	}
}
