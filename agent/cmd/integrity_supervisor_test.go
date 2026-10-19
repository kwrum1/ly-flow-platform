package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestAgentIntegrityTamper_fails_closed_and_emits_canonical_control_health(t *testing.T) {
	// Given
	artifactPath, signaturePath, rootPath := signedArtifactFixture(t, []byte("trusted-agent"))
	if err := os.WriteFile(artifactPath, []byte("tampered-agent"), 0o700); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}

	received := make(chan contracts.TelemetryEnvelope, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var envelope struct {
			Values map[string]interface{} `json:"values"`
		}
		if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
			t.Errorf("decode control-health transport: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		data, ok := envelope.Values["data"].(string)
		if !ok {
			t.Errorf("control-health transport data is not a string")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var event contracts.TelemetryEnvelope
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			t.Errorf("decode control-health event: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- event
		_, _ = writer.Write([]byte(`{"code":0}`))
	}))
	defer server.Close()

	agent := NewAgent(&Config{
		API: server.URL, AgentID: "agent-integrity", AgentKey: "agent-key",
		RuntimeTelemetryStream: "telemetry:runtime", SpoolEnabled: true,
		SpoolDir: t.TempDir(), SpoolMaxBytes: 1 << 20, SpoolFlushInterval: 60,
		AgentBinaryDigestPath: signaturePath, AgentBinaryRootPath: rootPath,
		RequireAgentIntegrity: true,
	})
	agent.agentID = "agent-integrity"
	agent.agentKey = "agent-key"

	// When
	err := agent.verifyAgentStartupIntegrity(context.Background(), artifactPath)

	// Then
	if !errors.Is(err, errAgentBinaryIntegrity) {
		t.Fatalf("integrity result = %v, want errAgentBinaryIntegrity", err)
	}
	health := agent.runtimeHealth.Snapshot()
	if health.PreventionEnabled || health.Reason != "binary_integrity_failed" {
		t.Fatalf("tampered artifact did not fail closed: %+v", health)
	}
	select {
	case event := <-received:
		if event.SchemaVersion != contracts.TelemetrySchemaVersion || event.EventType != controlHealthEventType {
			t.Fatalf("non-canonical control-health event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canonical control-health event")
	}
}

func TestAgentIntegrity_explicitly_disabled_skips_default_signature_paths(t *testing.T) {
	agent := NewAgent(&Config{
		RequireAgentIntegrity:    false,
		RequireConfigIntegrity:   false,
		AgentBinaryDigestPath:    "/nonexistent/agent-binary.digest.json",
		AgentConfigSignaturePath: "/nonexistent/agent-config.digest.json",
		AgentBinaryRootPath:      "/nonexistent/agent-binary-root.pem",
		AgentConfigRootPath:      "/nonexistent/agent-config-root.pem",
	})
	if err := agent.verifyAgentStartupIntegrity(context.Background(), "/nonexistent/agent"); err != nil {
		t.Fatalf("explicitly disabled integrity checks were not skipped: %v", err)
	}
}

func TestSignedConfigIntegrity_rejects_tampered_config(t *testing.T) {
	// Given
	configPath, signaturePath, rootPath := signedArtifactFixture(t, []byte("signed-config"))
	if err := os.WriteFile(configPath, []byte("tampered-config"), 0o600); err != nil {
		t.Fatalf("tamper config: %v", err)
	}

	// When
	err := verifySignedConfigIntegrity(context.Background(), configPath, signaturePath, rootPath)

	// Then
	if !errors.Is(err, errAgentConfigIntegrity) {
		t.Fatalf("config integrity result = %v, want errAgentConfigIntegrity", err)
	}
}

func TestSignedArtifactIntegrity_streams_and_accepts_matching_digest(t *testing.T) {
	// Given
	contents := make([]byte, 2<<20)
	for index := range contents {
		contents[index] = byte(index % 251)
	}
	artifactPath, signaturePath, rootPath := signedArtifactFixture(t, contents)

	// When
	err := verifySignedArtifactIntegrity(context.Background(), artifactPath, signaturePath, rootPath, errAgentBinaryIntegrity)

	// Then
	if err != nil {
		t.Fatalf("verify matching streamed artifact: %v", err)
	}
}

func TestSignedConfigEnrollment_persists_mutable_identity_separately(t *testing.T) {
	// Given
	configPath := filepath.Join(t.TempDir(), "agent.yaml")
	original := []byte("server:\n  api: signed\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatalf("write signed config fixture: %v", err)
	}
	identityPath := filepath.Join(t.TempDir(), "agent-identity.yaml")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"code":0,"data":{"agent_id":"signed-agent","agent_key":"signed-key"}}`))
	}))
	defer server.Close()
	agent := NewAgent(&Config{
		API: server.URL, AgentConfigPath: configPath, AgentIdentityPath: identityPath,
		RequireConfigIntegrity: true,
	})

	// When
	err := agent.enroll()

	// Then
	if err != nil {
		t.Fatalf("enroll with signed config: %v", err)
	}
	unchanged, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read signed config: %v", err)
	}
	if string(unchanged) != string(original) {
		t.Fatalf("signed config was mutated: %q", unchanged)
	}
	identity := &Config{}
	values, err := parseSimpleYAML(identityPath)
	if err != nil {
		t.Fatalf("read identity config: %v", err)
	}
	applyAgentIdentity(identity, values)
	if identity.AgentID != "signed-agent" || identity.AgentKey != "signed-key" {
		t.Fatalf("persisted identity = id %q key %q", identity.AgentID, identity.AgentKey)
	}
}

func TestProductionEngineSupervisor_restarts_after_stale_watchdog_and_honors_budget(t *testing.T) {
	// Given
	var attempts atomic.Int32
	started := make(chan struct{}, 2)
	clock := newTestRuntimeClock(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC))
	health := newRuntimeControlHealth("agent-runtime", RuntimeLimits{RestartBudget: 1}, clock.Now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := func(runContext context.Context) {
		attempts.Add(1)
		started <- struct{}{}
		<-runContext.Done()
	}

	// When
	done := make(chan struct{})
	go func() {
		runSupervisedRuntime(ctx, health, runtimeSupervisorConfig{
			Name: "test-adapter", StaleAfter: time.Second, CheckEvery: 5 * time.Millisecond,
			Run: run,
		})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not start adapter")
	}
	clock.Advance(2 * time.Second)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not restart stale adapter")
	}
	clock.Advance(2 * time.Second)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop after restart budget exhaustion")
	}

	// Then
	snapshot := health.Snapshot()
	if attempts.Load() != 2 || snapshot.RestartCount != 1 || snapshot.Reason != "restart_budget_exhausted" || snapshot.PreventionEnabled {
		t.Fatalf("supervisor attempts=%d health=%+v", attempts.Load(), health.Snapshot())
	}
}

type testRuntimeClock struct {
	current atomic.Int64
}

func newTestRuntimeClock(initial time.Time) *testRuntimeClock {
	clock := &testRuntimeClock{}
	clock.current.Store(initial.UnixNano())
	return clock
}

func (clock *testRuntimeClock) Now() time.Time {
	return time.Unix(0, clock.current.Load()).UTC()
}

func (clock *testRuntimeClock) Advance(delta time.Duration) {
	clock.current.Add(int64(delta))
}

func signedArtifactFixture(t *testing.T, contents []byte) (string, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate integrity key: %v", err)
	}
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(artifactPath, contents, 0o700); err != nil {
		t.Fatalf("write integrity artifact: %v", err)
	}
	digest := sha256.Sum256(contents)
	fingerprint := policyRootFingerprint(publicKey)
	payload := signedDigestPayload{SchemaVersion: signedDigestSchemaVersion, Artifact: filepath.Base(artifactPath), Digest: hex.EncodeToString(digest[:]), SignerFingerprint: fingerprint}
	signature := ed25519.Sign(privateKey, payload.bytes())
	digestFile := signedDigestEnvelope{Payload: payload, Signature: hex.EncodeToString(signature)}
	encoded, err := json.Marshal(digestFile)
	if err != nil {
		t.Fatalf("marshal integrity envelope: %v", err)
	}
	signaturePath := filepath.Join(dir, "artifact.digest.json")
	if err := os.WriteFile(signaturePath, encoded, 0o600); err != nil {
		t.Fatalf("write integrity envelope: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal integrity root: %v", err)
	}
	rootPath := filepath.Join(dir, "integrity-root.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write integrity root: %v", err)
	}
	return artifactPath, signaturePath, rootPath
}
