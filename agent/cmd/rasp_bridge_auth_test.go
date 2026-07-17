package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestRASPBridgeTokenRotation_accepts_overlap_then_rejects_stale_token(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	bridge := newTestRASPBridge(t, func() time.Time { return now }, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
	if err := bridge.RotateToken("bridge-token-next"); err != nil {
		t.Fatalf("rotate bridge token: %v", err)
	}

	// When
	overlap := performRASPBridgeRequest(bridge.Handler(), http.MethodGet, raspBridgeConfigPath, "bridge-token-current", nil)
	now = now.Add(time.Minute + time.Nanosecond)
	stale := performRASPBridgeRequest(bridge.Handler(), http.MethodGet, raspBridgeConfigPath, "bridge-token-current", nil)

	// Then
	if overlap.Code != http.StatusOK {
		t.Fatalf("overlap status = %d body = %s", overlap.Code, overlap.Body.String())
	}
	if stale.Code != http.StatusUnauthorized {
		t.Fatalf("stale status = %d body = %s", stale.Code, stale.Body.String())
	}
}

func TestRASPBridgeConfigPull_requires_token_and_agent_binding(t *testing.T) {
	// Given
	bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})

	// When
	missingToken := performRASPBridgeRequest(bridge.Handler(), http.MethodGet, raspBridgeConfigPath, "", nil)
	wrongAgentRequest := httptest.NewRequest(http.MethodGet, raspBridgeConfigPath, nil)
	wrongAgentRequest.Header.Set(raspBridgeTokenHeader, "bridge-token-current")
	wrongAgentRequest.Header.Set(raspBridgeAgentHeader, "other-agent")
	wrongAgent := httptest.NewRecorder()
	bridge.Handler().ServeHTTP(wrongAgent, wrongAgentRequest)

	// Then
	if missingToken.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", missingToken.Code)
	}
	if wrongAgent.Code != http.StatusForbidden {
		t.Fatalf("wrong agent status = %d", wrongAgent.Code)
	}
	health := bridge.agent.runtimeHealth.Snapshot()
	if health.Reason != "authorization_failed" || health.PreventionEnabled {
		t.Fatalf("authorization failure did not fail closed: %+v", health)
	}
}

func TestRASPBridgeRuntime_rejects_unauthenticated_listener_configuration(t *testing.T) {
	// Given
	config := raspBridgeRuntimeConfig{
		FallbackPath:  t.TempDir() + "/fallback.jsonl",
		QueueCapacity: 1,
		TokenOverlap:  time.Minute,
		Now:           time.Now,
		Publisher:     &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)},
	}

	// When
	_, err := newRASPBridgeRuntime(newActiveRASPBridgeAgent(t), config)

	// Then
	if err == nil {
		t.Fatal("RASP bridge accepted empty authentication token")
	}
}

func TestRASPBridgeEvent_rejects_wrong_policy_binding_and_unknown_schema(t *testing.T) {
	// Given
	bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
	body := validRASPBridgeBody(t)
	wrongPolicy := bytes.Replace(body, []byte(`"policy_version":12`), []byte(`"policy_version":11`), 1)
	unknownSchema := bytes.Replace(body, []byte(`"evidence":"echo todo12-inert"`), []byte(`"evidence":"echo todo12-inert","arbitrary":{"nested":true}`), 1)

	// When
	policyResponse := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", wrongPolicy)
	schemaResponse := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", unknownSchema)

	// Then
	if policyResponse.Code != http.StatusConflict {
		t.Fatalf("wrong policy status = %d body = %s", policyResponse.Code, policyResponse.Body.String())
	}
	if schemaResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown schema status = %d body = %s", schemaResponse.Code, schemaResponse.Body.String())
	}
}

func TestRASPBridgeEvent_rejects_body_over_one_mibibyte(t *testing.T) {
	// Given
	bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
	oversized := []byte(`{"schema_version":"` + raspBridgeEventSchemaVersion + `","evidence":"` + strings.Repeat("a", agentRuntimeLimits().MemoryBytes) + `"}`)

	// When
	response := performRASPBridgeRequest(bridge.Handler(), http.MethodPost, raspBridgeEventsPath, "bridge-token-current", oversized)

	// Then
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d body = %s", response.Code, response.Body.String())
	}
}

func TestRASPBridgeAddress_allows_only_loopback_or_unix_socket(t *testing.T) {
	for _, address := range []string{"0.0.0.0:17891", "192.0.2.20:17891", ":17891"} {
		if err := validateRASPBridgeAddress(address); err == nil {
			t.Fatalf("address %q accepted", address)
		}
	}
	for _, address := range []string{"127.0.0.1:17891", "localhost:17891", "[::1]:17891", "unix:///tmp/lyflow-rasp.sock"} {
		if err := validateRASPBridgeAddress(address); err != nil {
			t.Fatalf("address %q rejected: %v", address, err)
		}
	}
}

func TestRASPBridgeConfigPull_returns_current_bound_policy(t *testing.T) {
	bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
	response := performRASPBridgeRequest(bridge.Handler(), http.MethodGet, raspBridgeConfigPath, "bridge-token-current", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("config status = %d body = %s", response.Code, response.Body.String())
	}
	var config raspBridgeConfigResponse
	if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	if config.AgentID != "agent-todo12" || config.PolicyID != "rasp-policy-todo12" || config.PolicyVersion != 12 || config.BridgeToken != "bridge-token-current" {
		t.Fatalf("unexpected config binding: %+v", config)
	}
}
