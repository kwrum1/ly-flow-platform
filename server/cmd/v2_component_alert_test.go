package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestAgentComponentAlertHandlerRejectsInvalidAlert(t *testing.T) {
	cfg, _ := ingestionTestConfig(t, 10)
	req := authenticatedIngestionRequest(http.MethodPost, "/api/v1/agent/component-alert", `{"schema_version":"bad"}`)
	rec := httptest.NewRecorder()
	agentComponentAlertHandler(cfg).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "invalid_component_alert" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestDecodeComponentAlertsAcceptsSingleAndBatch(t *testing.T) {
	single := `{"schema_version":"lyflow.component_alert.v1","id":"a1"}`
	alerts, err := decodeComponentAlerts(json.RawMessage(single))
	if err != nil || len(alerts) != 1 || alerts[0].ID != "a1" {
		t.Fatalf("single decode = %#v, %v", alerts, err)
	}
	batch := `[{"schema_version":"lyflow.component_alert.v1","id":"a1"},{"schema_version":"lyflow.component_alert.v1","id":"a2"}]`
	alerts, err = decodeComponentAlerts(json.RawMessage(batch))
	if err != nil || len(alerts) != 2 || alerts[1].ID != "a2" {
		t.Fatalf("batch decode = %#v, %v", alerts, err)
	}
	if _, err := decodeComponentAlerts(json.RawMessage(`[]`)); err == nil {
		t.Fatal("empty batch accepted")
	}
}

func TestStoreV2ComponentAlertRequiresRedis(t *testing.T) {
	alert := contracts.ComponentAlert{SchemaVersion: contracts.ComponentAlertSchemaVersion, ID: "a1", Category: contracts.TelemetryNetwork, SourceEngine: contracts.SourceEngineSuricata, RuleID: "1:1", RuleName: "test", Severity: contracts.SeverityHigh, ScoreHint: 80, OccurredAt: time.Now(), Source: "suricata", Summary: "test"}
	if _, err := storeV2ComponentAlert(httptest.NewRequest(http.MethodPost, "/", nil).Context(), &Config{}, alert); err == nil {
		t.Fatal("expected redis unavailable error")
	}
}

func TestComponentAlertCategoryMatchesV2Aliases(t *testing.T) {
	if !componentAlertCategoryMatches("traffic", "network") {
		t.Fatal("traffic should match v2 network category")
	}
	if !componentAlertCategoryMatches("log_audit", "log") {
		t.Fatal("log_audit should match v2 log category")
	}
	if componentAlertCategoryMatches("rasp", "network") {
		t.Fatal("rasp should not match network")
	}
}

func TestComponentAlertUnifiedOverrides(t *testing.T) {
	event := (&ConsumerState{}).toUnifiedXDREvent("component_alerts:v2", "1-0", map[string]interface{}{
		"schema_version": "lyflow.component_alert.v1",
		"id":             "alert-1",
		"category":       "network",
		"source_engine":  "suricata",
		"rule_id":        "1:2010935",
		"rule_name":      "ET MALWARE Example",
		"severity":       "high",
		"score_hint":     75,
		"summary":        "network alert",
		"entities":       map[string]interface{}{"agent_id": "agent-1", "source_ip": "10.0.0.1", "target_ip": "10.0.0.2"},
	})
	if event.Module != "dpi" || event.SourceModule != "dpi" || event.Source != "suricata" || event.EventType != "suricata.alert" {
		t.Fatalf("component alert was not projected as engine event: %+v", event)
	}
	if event.EntityIDs == nil || event.EntityIDs.AgentID != "agent-1" || event.SrcIP != "10.0.0.1" || event.DstIP != "10.0.0.2" {
		t.Fatalf("entities not preserved: %+v", event)
	}
	if event.BehaviorContext == nil || event.BehaviorContext.Details["component_rule_id"] != "1:2010935" {
		t.Fatalf("rule evidence not preserved: %+v", event.BehaviorContext)
	}
}
