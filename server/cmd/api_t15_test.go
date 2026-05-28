package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeriveIncidentsReturnsCorrelatedChain(t *testing.T) {
	events := []map[string]interface{}{
		{"id": "evt-1", "event_type": "xdr.rasp.sql_injection", "severity": "high", "message": "initial_access sql injection", "agent_id": "agent-1", "chain_id": "chain-1", "created_at": "2026-05-13T10:00:00Z"},
		{"id": "evt-2", "event_type": "xdr.runtime.command", "severity": "critical", "message": "execution suspicious process", "agent_id": "agent-1", "chain_id": "chain-1", "created_at": "2026-05-13T10:01:00Z"},
	}
	incidents := deriveIncidents(events)
	if len(incidents) != 1 {
		t.Fatalf("expected one incident, got %d", len(incidents))
	}
	if incidents[0]["severity"] != "critical" || incidents[0]["event_count"] != 2 {
		t.Fatalf("unexpected incident summary: %#v", incidents[0])
	}
	stages, ok := incidents[0]["stages"].([]string)
	if !ok || len(stages) < 2 {
		t.Fatalf("expected multi-stage incident, got %#v", incidents[0]["stages"])
	}
	if title, ok := incidents[0]["title"].(string); !ok || title == "" {
		t.Fatalf("expected Chinese incident title, got %#v", incidents[0]["title"])
	}
	if chain, ok := incidents[0]["attack_chain"].([]map[string]interface{}); !ok || len(chain) < 2 {
		t.Fatalf("expected attack chain evidence, got %#v", incidents[0]["attack_chain"])
	}
}

func TestBuildTimelineOrdersByTimestamp(t *testing.T) {
	events := []map[string]interface{}{
		{"id": "evt-2", "event_type": "xdr.runtime.command", "severity": "critical", "agent_id": "agent-1", "created_at": "2026-05-13T10:01:00Z"},
		{"id": "evt-1", "event_type": "xdr.rasp.sql_injection", "severity": "high", "agent_id": "agent-1", "created_at": "2026-05-13T10:00:00Z"},
	}
	items := buildTimeline(events, "agent:agent-1", "")
	if len(items) != 2 {
		t.Fatalf("expected two timeline items, got %d", len(items))
	}
	if items[0]["event_id"] != "evt-1" || items[1]["event_id"] != "evt-2" {
		t.Fatalf("timeline not ordered by timestamp: %#v", items)
	}
	if items[0]["stage_label"] == "" || items[0]["summary"] == "" {
		t.Fatalf("expected readable Chinese timeline labels: %#v", items[0])
	}
}

func TestTimelineDetailInvalidIDReturnsJSON404(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/timeline/does-not-exist", nil)
	rec := httptest.NewRecorder()
	timelineDetailHandler(&Config{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if body["error_code"] != "timeline_not_found" {
		t.Fatalf("unexpected error response: %#v", body)
	}
}
