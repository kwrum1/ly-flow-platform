package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

type channelRASPBridgePublisher struct {
	events chan contracts.TelemetryEnvelope
	err    error
}

func (p *channelRASPBridgePublisher) Publish(_ context.Context, event contracts.TelemetryEnvelope) error {
	if p.err != nil {
		return p.err
	}
	p.events <- event
	return nil
}

func newActiveRASPBridgeAgent(t *testing.T) *Agent {
	t.Helper()
	healthServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"code":0}`))
	}))
	t.Cleanup(healthServer.Close)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate RASP policy signing key: %v", err)
	}
	agent := NewAgent(&Config{
		API:                    healthServer.URL,
		AgentKey:               "agent-todo12-key",
		RASPTelemetryStream:    "telemetry:rasp",
		RASPPolicyRootPath:     writeAgentPolicyRoot(t, publicKey),
		RuntimeTelemetryStream: "telemetry:runtime",
		SpoolEnabled:           true,
		SpoolDir:               t.TempDir(),
		SpoolMaxBytes:          1 << 20,
		SpoolFlushInterval:     60,
	})
	agent.agentID = "agent-todo12"
	agent.agentKey = "agent-todo12-key"
	t.Cleanup(agent.Stop)
	agent.hostname = "todo12-host"
	agent.localIP = "127.0.0.1"
	agent.raspLanguages = []shared.Language{shared.LanguagePython, shared.LanguageJava}
	policy := shared.Policy{
		ID:           "rasp-policy-todo12",
		Version:      12,
		Owner:        "todo12-test",
		Mode:         shared.ModeMonitor,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		FailBehavior: shared.FailDisable,
		Limits:       shared.Limits{MaxEventsPerSecond: 100},
		Selectors:    shared.Selectors{AgentIDs: []string{"agent-todo12"}, Languages: []shared.Language{shared.LanguagePython, shared.LanguageJava}},
		AuditLink:    "audit://todo12-test",
	}
	envelope := signAgentPolicy(t, privateKey, publicKey, policy)
	if err := agent.applySignedRASPPolicy(envelope); err != nil {
		t.Fatalf("apply signed RASP policy assignment: %v", err)
	}
	if err := agent.activateAcknowledgedRASPPolicy(envelope); err != nil {
		t.Fatalf("activate signed RASP policy assignment: %v", err)
	}
	return agent
}

func newTestRASPBridge(t *testing.T, now func() time.Time, capacity int, startWorker bool, publisher raspBridgePublisher) *raspBridgeRuntime {
	t.Helper()
	bridge, err := newRASPBridgeRuntime(newActiveRASPBridgeAgent(t), raspBridgeRuntimeConfig{
		CurrentToken:  "bridge-token-current",
		FallbackPath:  t.TempDir() + "/rasp-fallback.jsonl",
		QueueCapacity: capacity,
		TokenOverlap:  time.Minute,
		Now:           now,
		Publisher:     publisher,
		StartWorker:   startWorker,
	})
	if err != nil {
		t.Fatalf("create RASP bridge: %v", err)
	}
	t.Cleanup(bridge.Close)
	return bridge
}

func validRASPBridgeBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(raspBridgeEventRequest{
		SchemaVersion: raspBridgeEventSchemaVersion,
		EventID:       "python-inert-1",
		AgentID:       "agent-todo12",
		PolicyID:      "rasp-policy-todo12",
		PolicyVersion: 12,
		Language:      shared.LanguagePython,
		EventType:     raspBridgeEventCommand,
		Severity:      contracts.SeverityLow,
		ObservedAt:    time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
		Application:   "todo12-fixture",
		RuleID:        "inert-command-observation",
		Evidence:      "echo todo12-inert",
	})
	if err != nil {
		t.Fatalf("marshal RASP bridge request: %v", err)
	}
	return body
}

func performRASPBridgeRequest(handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(raspBridgeTokenHeader, token)
	request.Header.Set(raspBridgeAgentHeader, "agent-todo12")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
