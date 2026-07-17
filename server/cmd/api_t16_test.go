package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentidentity"
)

func TestHTTPAgentEnrollmentUsesOneTimeTokenAndServerIdentity(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	token, err := manager.IssueEnrollmentToken("agent-http", time.Minute)
	if err != nil {
		t.Fatalf("issue enrollment token: %v", err)
	}
	handler := agentEnrollHandler(&Config{AgentIdentity: manager})
	body := `{"enrollment_token":"` + token + `","hostname":"untrusted-host","ip":"192.0.2.30"}`

	// When
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body)))

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("enrollment status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			AgentID  string `json:"agent_id"`
			AgentKey string `json:"agent_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Data.AgentID != "agent-http" {
		t.Fatalf("agent id = %q", response.Data.AgentID)
	}
	if err := manager.Authenticate(response.Data.AgentID, response.Data.AgentKey, agentidentity.TransportHTTP); err != nil {
		t.Fatalf("authenticate issued credential: %v", err)
	}
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body)))
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replayed enrollment status = %d body = %s", replay.Code, replay.Body.String())
	}
}

func TestSanitizeAgentRecordOmitsSecrets(t *testing.T) {
	record := sanitizeAgentRecord(map[string]interface{}{
		"agent_id":     "agent-1",
		"agent_key":    "secret-key",
		"token":        "secret-token",
		"capabilities": map[string]interface{}{"runtime_sensor": map[string]interface{}{"enabled": true}},
	})
	if _, ok := record["agent_key"]; ok {
		t.Fatal("agent_key leaked")
	}
	if _, ok := record["token"]; ok {
		t.Fatal("token leaked")
	}
	if record["capabilities"] == nil {
		t.Fatal("capabilities missing")
	}
}

func TestAgentConfigWithoutKeyDeniedJSON(t *testing.T) {
	body := bytes.NewBufferString(`{"agent_id":"agent-1"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/config", body)
	rec := httptest.NewRecorder()
	agentConfigHandler(&Config{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "agent_auth_required" {
		t.Fatalf("unexpected response: %#v", payload)
	}
}

func TestAgentTrafficEventWithoutKeyDeniedJSON(t *testing.T) {
	body := bytes.NewBufferString(`{"agent_id":"agent-1","stream":"sessions:semantic","type":"semantic_session","data":"{}"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/traffic-event", body)
	rec := httptest.NewRecorder()
	agentTrafficEventHandler(&Config{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "agent_auth_required" {
		t.Fatalf("unexpected response: %#v", payload)
	}
}

func TestEngineDesiredStatesForAgentFollowToggles(t *testing.T) {
	states := engineDesiredStatesForAgent(false, true, false)
	seen := map[string]bool{}
	for _, state := range states {
		name, _ := state["name"].(string)
		enabled, _ := state["enabled"].(bool)
		seen[name] = true
		switch name {
		case "suricata", "rasp":
			if enabled {
				t.Fatalf("%s enabled=true, want false", name)
			}
		case "wazuh", "yara":
			if !enabled {
				t.Fatalf("%s enabled=false, want true", name)
			}
		}
	}
	for _, name := range []string{"suricata", "wazuh", "yara", "rasp"} {
		if !seen[name] {
			t.Fatalf("missing desired state %s", name)
		}
	}
}
