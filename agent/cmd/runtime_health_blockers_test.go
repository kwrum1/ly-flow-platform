package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestControlHealthPublication_returns_delivery_error(t *testing.T) {
	// Given
	agent := NewAgent(&Config{RuntimeTelemetryStream: "telemetry:runtime"})
	defer agent.cancel()

	// When
	err := agent.publishControlHealth(agent.runtimeHealth.Snapshot())

	// Then
	if err == nil || !strings.Contains(err.Error(), "spool") {
		t.Fatalf("control-health publication error = %v, want spool delivery error", err)
	}
	snapshot := agent.runtimeHealth.Snapshot()
	if snapshot.Publication.Status != controlHealthDegraded || snapshot.Publication.RetryCount != 3 || snapshot.Publication.LastError == "" {
		t.Fatalf("control-health publication state = %+v, want three failed attempts", snapshot.Publication)
	}
}

func TestFailClosedIntegrity_preserves_integrity_and_publication_errors(t *testing.T) {
	// Given
	agent := NewAgent(&Config{RuntimeTelemetryStream: "telemetry:runtime"})
	defer agent.cancel()
	integrityErr := errors.New("fixture integrity failure")

	// When
	err := agent.failClosedIntegrity("binary_integrity_failed", integrityErr)

	// Then
	if !errors.Is(err, integrityErr) || !strings.Contains(err.Error(), "spool") {
		t.Fatalf("fail-closed error = %v, want integrity and publication errors", err)
	}
}

func TestRASPBridgeControlHealth_matches_canonical_schema_exactly(t *testing.T) {
	// Given
	bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
	want := []string{"event_type", "fail_policy", "limits", "prevention_enabled", "publication", "reason", "restart_count", "runtime", "schema_version", "status", "watchdog_at"}

	// When
	bridgeFields := jsonFieldNames(t, bridge.Health())
	agentFields := jsonFieldNames(t, bridge.agent.runtimeHealth.Snapshot())

	// Then
	if strings.Join(bridgeFields, ",") != strings.Join(want, ",") {
		t.Fatalf("bridge control-health fields = %v, want %v", bridgeFields, want)
	}
	if strings.Join(bridgeFields, ",") != strings.Join(agentFields, ",") {
		t.Fatalf("bridge fields = %v, agent fields = %v", bridgeFields, agentFields)
	}
}

func TestRuntimeControlHealth_publication_recovery_preserves_fail_closed_policy(t *testing.T) {
	// Given
	health := newRuntimeControlHealth("agent-runtime", agentRuntimeLimits(), time.Now)
	health.setPreventionEnabled(true)
	health.Degrade("binary_integrity_failed", true)
	health.recordPublicationFailure(errors.New("fixture publication outage"))

	// When
	health.recordPublicationSuccess()
	snapshot := health.Snapshot()

	// Then
	if snapshot.Status != controlHealthDegraded || snapshot.Reason != "binary_integrity_failed" || snapshot.PreventionEnabled {
		t.Fatalf("publication recovery overrode fail-closed health: %+v", snapshot)
	}
	if snapshot.Publication.Status != controlHealthHealthy || snapshot.Publication.RetryCount != 1 || snapshot.Publication.LastError != "" {
		t.Fatalf("publication recovery state = %+v", snapshot.Publication)
	}
}

func TestRASPBridgeHTTPHandlers_record_JSON_encoding_errors(t *testing.T) {
	tests := []struct {
		name string
		call func(*raspBridgeRuntime, http.ResponseWriter)
	}{
		{name: "event", call: func(bridge *raspBridgeRuntime, writer http.ResponseWriter) {
			request := authenticatedRASPBridgeRequest(t, http.MethodPost, raspBridgeEventsPath, validRASPBridgeBody(t))
			bridge.handleEvent(writer, request)
		}},
		{name: "config", call: func(bridge *raspBridgeRuntime, writer http.ResponseWriter) {
			request := authenticatedRASPBridgeRequest(t, http.MethodGet, raspBridgeConfigPath, nil)
			bridge.handleConfig(writer, request)
		}},
		{name: "health", call: func(bridge *raspBridgeRuntime, writer http.ResponseWriter) {
			request := authenticatedRASPBridgeRequest(t, http.MethodGet, raspBridgeHealthPath, nil)
			bridge.handleHealth(writer, request)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
			writer := &failingJSONResponseWriter{header: make(http.Header)}

			// When
			test.call(bridge, writer)

			// Then
			bridge.healthMu.RLock()
			lastError := bridge.lastError
			bridge.healthMu.RUnlock()
			if !strings.Contains(lastError, "encode JSON response") {
				t.Fatalf("handler error = %q, want JSON encoding failure", lastError)
			}
		})
	}
}

func TestRASPBridgeHealth_POST_accepts_canonical_child_health_and_propagates(t *testing.T) {
	// Given
	bridge := newTestRASPBridge(t, time.Now, 4, false, &channelRASPBridgePublisher{events: make(chan contracts.TelemetryEnvelope, 1)})
	health := bridge.Health()
	health.Runtime = "python-rasp"
	body, err := json.Marshal(health)
	if err != nil {
		t.Fatalf("marshal child control health: %v", err)
	}
	request := authenticatedRASPBridgeRequest(t, http.MethodPost, raspBridgeHealthPath, body)
	response := httptest.NewRecorder()

	// When
	bridge.handleHealth(response, request)

	// Then
	if response.Code != http.StatusAccepted {
		t.Fatalf("control health POST status = %d body=%s", response.Code, response.Body.String())
	}
}

func jsonFieldNames(t *testing.T, value interface{}) []string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal schema value: %v", err)
	}
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode schema fields: %v", err)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func authenticatedRASPBridgeRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("create RASP bridge request: %v", err)
	}
	request.Header.Set(raspBridgeTokenHeader, "bridge-token-current")
	request.Header.Set(raspBridgeAgentHeader, "agent-todo12")
	return request
}

type failingJSONResponseWriter struct {
	header http.Header
	status int
}

func (writer *failingJSONResponseWriter) Header() http.Header { return writer.header }

func (writer *failingJSONResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("fixture response write failure")
}

func (writer *failingJSONResponseWriter) WriteHeader(status int) { writer.status = status }
