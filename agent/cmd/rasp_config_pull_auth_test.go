package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentConfigPull_authenticates_request_headers_and_body(t *testing.T) {
	// Given
	requestSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Lyflow-Agent-ID") != "agent-config-auth" {
			t.Errorf("agent header = %q", r.Header.Get("X-Lyflow-Agent-ID"))
		}
		if r.Header.Get("Authorization") != "Bearer agent-config-secret" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		var request struct {
			AgentID  string `json:"agent_id"`
			AgentKey string `json:"agent_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode config request: %v", err)
		}
		if request.AgentID != "agent-config-auth" || request.AgentKey != "agent-config-secret" {
			t.Errorf("body credentials = %+v", request)
		}
		requestSeen <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"success","data":{"config":{},"engine_desired_states":[],"tasks":[]}}`))
	}))
	defer server.Close()
	agent := NewAgent(&Config{API: server.URL})
	agent.agentID = "agent-config-auth"
	agent.agentKey = "agent-config-secret"

	// When
	agent.pullConfigAndReportTasks()

	// Then
	select {
	case <-requestSeen:
	default:
		t.Fatal("authenticated config request was not observed")
	}
}
