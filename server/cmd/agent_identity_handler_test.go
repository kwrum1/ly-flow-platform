package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentidentity"
)

func TestAgentIdentityControlRetiresAndRecoversSameID(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	handler := agentIdentityControlHandler(&Config{AgentIdentity: manager})
	enrollment := invokeIdentityControl(t, handler, map[string]interface{}{
		"action": "issue_enrollment", "agent_id": "agent-control", "ttl_minutes": 5,
	})
	token, _ := enrollment["enrollment_token"].(string)
	record, err := manager.Enroll(token, "legacy", agentidentity.EnabledTransports{HTTP: true})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := manager.Transition(record.ID(), agentidentity.StateLegacyVerified, record.Version()); err != nil {
		t.Fatalf("legacy verified: %v", err)
	}
	if err := manager.Transition(record.ID(), agentidentity.StateHashMigrated, record.Version()); err != nil {
		t.Fatalf("hash migrated: %v", err)
	}
	if err := manager.BeginRotation(record.ID(), "new", time.Hour, record.Version()); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}
	if err := manager.Authenticate(record.ID().String(), "new", agentidentity.TransportHTTP); err != nil {
		t.Fatalf("confirm new credential: %v", err)
	}

	// When
	invokeIdentityControl(t, handler, map[string]interface{}{
		"action": "retire_legacy", "agent_id": record.ID().String(), "version": record.Version(),
	})
	recovery := invokeIdentityControl(t, handler, map[string]interface{}{
		"action": "issue_recovery", "agent_id": record.ID().String(), "ttl_minutes": 5,
	})
	recovered := invokeIdentityControl(t, handler, map[string]interface{}{
		"action": "recover", "agent_id": record.ID().String(), "token": recovery["recovery_token"],
	})

	// Then
	if recovered["agent_id"] != record.ID().String() {
		t.Fatalf("recovered agent id = %v", recovered["agent_id"])
	}
	credential, _ := recovered["agent_credential"].(string)
	if err := manager.Authenticate(record.ID().String(), credential, agentidentity.TransportHTTP); err != nil {
		t.Fatalf("authenticate recovered credential: %v", err)
	}
}

func invokeIdentityControl(t *testing.T, handler http.Handler, request map[string]interface{}) map[string]interface{} {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/agent/identity", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("identity control status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response.Data
}
