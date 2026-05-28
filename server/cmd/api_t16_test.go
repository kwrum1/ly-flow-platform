package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
