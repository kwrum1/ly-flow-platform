package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

func TestAgentRASPPolicy_verifies_applies_and_acknowledges_version(t *testing.T) {
	// Given
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rootPath := writeAgentPolicyRoot(t, publicKey)
	policy := agentPolicyFixture(time.Now().UTC().Add(time.Hour))
	fingerprint := policyRootFingerprint(publicKey)
	payload, err := shared.CanonicalBytes(policy, fingerprint)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	envelope := shared.SignedPolicy{Policy: policy, Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload)), SignerFingerprint: fingerprint}
	agent := NewAgent(&Config{RASPPolicyRootPath: rootPath})

	// When
	err = agent.applySignedRASPPolicy(envelope)

	// Then
	if err != nil {
		t.Fatalf("apply signed policy: %v", err)
	}
	if agent.cfg.RASPEnabled || agent.ackPolicyVersion != policy.Version {
		t.Fatalf("policy must remain pending until server ACK: enabled=%v ack=%d", agent.cfg.RASPEnabled, agent.ackPolicyVersion)
	}
	if agent.runtimeHealth.Snapshot().PreventionEnabled {
		t.Fatal("pending signed policy reported prevention enabled")
	}
	if err := agent.activateAcknowledgedRASPPolicy(envelope); err != nil {
		t.Fatalf("activate acknowledged policy: %v", err)
	}
	if !agent.cfg.RASPEnabled || agent.cfg.RASPMode != "monitor" {
		t.Fatalf("acknowledged policy not activated: enabled=%v mode=%q", agent.cfg.RASPEnabled, agent.cfg.RASPMode)
	}
	if !agent.runtimeHealth.Snapshot().PreventionEnabled {
		t.Fatal("acknowledged monitor policy reported prevention disabled")
	}
}

func TestAgentRASPPolicy_rejects_bad_signature_and_stale_version(t *testing.T) {
	// Given
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	agent := NewAgent(&Config{RASPPolicyRootPath: writeAgentPolicyRoot(t, publicKey)})
	agent.ackPolicyVersion = 3
	policy := agentPolicyFixture(time.Now().UTC().Add(time.Hour))
	policy.Version = 4

	// When
	badSignatureErr := agent.applySignedRASPPolicy(shared.SignedPolicy{Policy: policy, Signature: "00"})
	policy.Version = 2
	staleErr := agent.applySignedRASPPolicy(shared.SignedPolicy{Policy: policy, Signature: "00"})

	// Then
	if badSignatureErr == nil || staleErr == nil {
		t.Fatalf("bad signature error=%v stale error=%v", badSignatureErr, staleErr)
	}
	if agent.cfg.RASPEnabled {
		t.Fatal("rejected policy enabled RASP")
	}
}

func TestAgentRASPPolicy_rejects_language_mismatch_and_same_version_replacement(t *testing.T) {
	// Given
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	agent := NewAgent(&Config{RASPPolicyRootPath: writeAgentPolicyRoot(t, publicKey)})
	agent.raspLanguages = []shared.Language{shared.LanguagePython}
	policy := agentPolicyFixture(time.Now().UTC().Add(time.Hour))
	policy.Selectors.Languages = []shared.Language{shared.LanguageJava}
	envelope := signAgentPolicy(t, privateKey, publicKey, policy)

	// When
	languageErr := agent.applySignedRASPPolicy(envelope)
	policy.Selectors.Languages = []shared.Language{shared.LanguagePython}
	accepted := signAgentPolicy(t, privateKey, publicKey, policy)
	if err := agent.applySignedRASPPolicy(accepted); err != nil {
		t.Fatalf("apply matching policy: %v", err)
	}
	policy.AuditLink = "audit://different"
	replacementErr := agent.applySignedRASPPolicy(signAgentPolicy(t, privateKey, publicKey, policy))

	// Then
	if !errors.Is(languageErr, errAgentPolicySelector) {
		t.Fatalf("language error = %v, want selector mismatch", languageErr)
	}
	if !errors.Is(replacementErr, errAgentPolicyReplacement) {
		t.Fatalf("replacement error = %v, want same-version replacement", replacementErr)
	}
	if err := agent.applySignedRASPPolicy(accepted); err != nil {
		t.Fatalf("exact signed envelope must be idempotent: %v", err)
	}
}

func TestAgentRASPPolicy_applies_expiry_fail_behavior_and_event_limit(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	agent := NewAgent(&Config{})
	agent.cfg.RASPEnabled = true
	agent.raspPolicyExpiresAt = now.Add(time.Second)
	agent.raspFailBehavior = shared.FailDisable
	agent.raspMaxEventsPerSecond = 2
	agent.raspPolicyACKed = true

	// When
	first := agent.allowRASPEvent(now)
	second := agent.allowRASPEvent(now)
	third := agent.allowRASPEvent(now)
	agent.enforceRASPPolicyExpiry(now.Add(2 * time.Second))

	// Then
	if !first || !second || third {
		t.Fatalf("rate limit decisions = %v,%v,%v, want true,true,false", first, second, third)
	}
	if agent.cfg.RASPEnabled {
		t.Fatal("fail-disable policy remained enabled after expiry")
	}

	// Given
	agent.cfg.RASPEnabled = true
	agent.raspPolicyExpiresAt = now.Add(time.Second)
	agent.raspPolicyExpired = false
	agent.raspFailBehavior = shared.FailMonitor

	// When
	agent.enforceRASPPolicyExpiry(now.Add(2 * time.Second))

	// Then
	if !agent.cfg.RASPEnabled || agent.cfg.RASPMode != string(shared.ModeMonitor) {
		t.Fatalf("fail-monitor fallback = enabled=%v mode=%q", agent.cfg.RASPEnabled, agent.cfg.RASPMode)
	}
}

func TestAgentRASPPolicy_fingerprint_is_signed_and_attributed(t *testing.T) {
	// Given
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	policy := agentPolicyFixture(time.Now().UTC().Add(time.Hour))
	envelope := signAgentPolicy(t, privateKey, publicKey, policy)
	envelope.SignerFingerprint = strings.Repeat("0", 64)
	agent := NewAgent(&Config{RASPPolicyRootPath: writeAgentPolicyRoot(t, publicKey)})

	// When
	err = agent.applySignedRASPPolicy(envelope)

	// Then
	if !errors.Is(err, errAgentPolicySignature) {
		t.Fatalf("fingerprint attribution error = %v, want signature error", err)
	}
}

func TestAgentRASPPolicy_accepts_signed_active_fallback_after_canary_expiry(t *testing.T) {
	// Given
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	agent := NewAgent(&Config{RASPPolicyRootPath: writeAgentPolicyRoot(t, publicKey)})
	canary := agentPolicyFixture(time.Now().UTC().Add(time.Hour))
	canary.Version = 2
	canary.Rollback.TargetVersion = 1
	canaryEnvelope := signAgentPolicy(t, privateKey, publicKey, canary)
	if err := agent.applySignedRASPPolicy(canaryEnvelope); err != nil {
		t.Fatalf("apply canary: %v", err)
	}
	if err := agent.activateAcknowledgedRASPPolicy(canaryEnvelope); err != nil {
		t.Fatalf("activate canary: %v", err)
	}
	agent.raspPolicyExpiresAt = time.Now().UTC().Add(-time.Second)
	active := agentPolicyFixture(time.Now().UTC().Add(2 * time.Hour))
	activeEnvelope := signAgentPolicy(t, privateKey, publicKey, active)

	// When
	err = agent.applySignedRASPPolicy(activeEnvelope)

	// Then
	if err != nil {
		t.Fatalf("apply active fallback: %v", err)
	}
	if agent.ackPolicyVersion != 1 || agent.cfg.RASPEnabled {
		t.Fatalf("fallback must be pending ACK: version=%d enabled=%v", agent.ackPolicyVersion, agent.cfg.RASPEnabled)
	}
}

func TestAgentProcess_live_server_keeps_RASP_pending_until_signed_assignment_ACK(t *testing.T) {
	// Given
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	policy := agentPolicyFixture(time.Now().UTC().Add(time.Hour))
	policy.Limits.MaxEventsPerSecond = 10
	envelope := signAgentPolicy(t, privateKey, publicKey, policy)
	var requests atomic.Int32
	var startedBeforeACK atomic.Bool
	var firstRequestEnabled atomic.Bool
	var agent *Agent
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			ACKVersion   uint64                 `json:"ack_policy_version"`
			Capabilities map[string]interface{} `json:"capabilities"`
		}
		if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		requestNumber := requests.Add(1)
		if probe, ok := body.Capabilities["rasp_probe_manager"].(map[string]interface{}); ok && probe["enabled"] == true {
			firstRequestEnabled.Store(true)
		}
		if requestNumber == 2 && agent.raspStarted {
			startedBeforeACK.Store(true)
		}
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"code": 0,
			"data": map[string]interface{}{
				"rasp_policy": envelope,
				"config":      map[string]interface{}{},
			},
		})
	}))
	defer server.Close()
	agent = NewAgent(&Config{
		API: server.URL, AgentID: "agent-live", AgentKey: "agent-key",
		RASPEnabled: true, RASPPolicyRootPath: writeAgentPolicyRoot(t, publicKey),
		RASPTelemetryStream: "", RASPBridgeAddr: "", AssetEnabled: false,
	})

	// When
	err = agent.Start()
	defer agent.Stop()

	// Then
	if err != nil {
		t.Fatalf("start Agent against live server: %v", err)
	}
	if requests.Load() != 2 || startedBeforeACK.Load() || firstRequestEnabled.Load() {
		t.Fatalf("requests=%d started_before_ack=%v unsigned_enabled=%v", requests.Load(), startedBeforeACK.Load(), firstRequestEnabled.Load())
	}
	if !agent.raspStarted || !agent.raspPolicyEnabled() {
		t.Fatalf("acknowledged signed policy not started: started=%v enabled=%v", agent.raspStarted, agent.raspPolicyEnabled())
	}
}

func agentPolicyFixture(expiresAt time.Time) shared.Policy {
	return shared.Policy{ID: "rasp-primary", Version: 1, Owner: "owner", Mode: shared.ModeMonitor, ExpiresAt: expiresAt, FailBehavior: shared.FailMonitor, AuditLink: "audit://fixture"}
}

func writeAgentPolicyRoot(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "policy-root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	return path
}

func signAgentPolicy(t *testing.T, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, policy shared.Policy) shared.SignedPolicy {
	t.Helper()
	fingerprint := policyRootFingerprint(publicKey)
	payload, err := shared.CanonicalBytes(policy, fingerprint)
	if err != nil {
		t.Fatalf("canonicalize policy: %v", err)
	}
	return shared.SignedPolicy{Policy: policy, Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload)), SignerFingerprint: fingerprint}
}
