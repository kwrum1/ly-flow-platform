package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

var (
	errAgentPolicySignature   = errors.New("agent RASP policy signature invalid")
	errAgentPolicyStale       = errors.New("agent RASP policy version stale")
	errAgentPolicyExpired     = errors.New("agent RASP policy expired")
	errAgentPolicySelector    = errors.New("agent RASP policy selector mismatch")
	errAgentPolicyReplacement = errors.New("agent RASP same-version replacement rejected")
	errAgentPolicyACK         = errors.New("agent RASP policy acknowledgement failed")
)

func (a *Agent) applySignedRASPPolicy(envelope shared.SignedPolicy) error {
	policy := envelope.Policy
	a.cfgMu.RLock()
	currentVersion := a.ackPolicyVersion
	currentEnvelope := a.raspPolicyEnvelope
	currentExpiresAt := a.raspPolicyExpiresAt
	a.cfgMu.RUnlock()
	rollbackFallback := policy.Version < currentVersion && !time.Now().UTC().Before(currentExpiresAt) && currentEnvelope.Policy.Rollback.TargetVersion == policy.Version
	if policy.Version < currentVersion && !rollbackFallback {
		return errAgentPolicyStale
	}
	if strings.TrimSpace(policy.Owner) == "" || strings.TrimSpace(policy.AuditLink) == "" {
		return fmt.Errorf("policy owner and audit link required: %w", errAgentPolicySignature)
	}
	if !agentSelected(policy.Selectors.AgentIDs, a.agentID) {
		return errAgentPolicySelector
	}
	if !agentLanguageSelected(policy.Selectors.Languages, a.raspLanguages) {
		return errAgentPolicySelector
	}
	switch policy.Mode {
	case shared.ModeMonitor, shared.ModeOff:
	case shared.ModeBlock:
		return fmt.Errorf("production block mode disabled: %w", errAgentPolicySignature)
	default:
		return fmt.Errorf("unsupported policy mode %q: %w", policy.Mode, errAgentPolicySignature)
	}
	publicKey, err := loadPolicyRoot(a.cfg.RASPPolicyRootPath)
	if err != nil {
		return err
	}
	if envelope.SignerFingerprint == "" || envelope.SignerFingerprint != policyRootFingerprint(publicKey) {
		return errAgentPolicySignature
	}
	payload, err := shared.CanonicalBytes(policy, envelope.SignerFingerprint)
	if err != nil {
		return fmt.Errorf("canonicalize RASP policy: %w", err)
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errAgentPolicySignature
	}
	if !policy.ExpiresAt.After(time.Now().UTC()) {
		return errAgentPolicyExpired
	}
	a.cfgMu.Lock()
	if policy.Version == a.ackPolicyVersion {
		if reflect.DeepEqual(envelope, a.raspPolicyEnvelope) {
			a.cfgMu.Unlock()
			return nil
		}
		a.cfgMu.Unlock()
		return errAgentPolicyReplacement
	}
	a.cfg.RASPEnabled = false
	a.cfg.RASPMode = string(shared.ModeOff)
	a.cfg.RASPPolicyVersion = policy.Version
	a.cfg.RASPBlockOnHit = false
	a.ackPolicyVersion = policy.Version
	a.ackPolicySignature = envelope.Signature
	a.raspPolicyEnvelope = envelope
	a.raspPolicyACKed = false
	a.raspPolicyExpiresAt = policy.ExpiresAt
	a.raspPolicyExpired = false
	a.raspFailBehavior = policy.FailBehavior
	a.raspMaxEventsPerSecond = policy.Limits.MaxEventsPerSecond
	a.raspRateWindow = time.Time{}
	a.raspRateCount = 0
	a.cfgMu.Unlock()
	a.setRuntimePreventionEnabled(false)
	return nil
}

func (a *Agent) activateAcknowledgedRASPPolicy(envelope shared.SignedPolicy) error {
	a.cfgMu.Lock()
	if !reflect.DeepEqual(envelope, a.raspPolicyEnvelope) || envelope.Policy.Version != a.ackPolicyVersion || envelope.Signature != a.ackPolicySignature {
		a.cfgMu.Unlock()
		return errAgentPolicyACK
	}
	if !envelope.Policy.ExpiresAt.After(time.Now().UTC()) {
		a.cfgMu.Unlock()
		return errAgentPolicyExpired
	}
	a.raspPolicyACKed = true
	a.cfg.RASPEnabled = envelope.Policy.Mode == shared.ModeMonitor
	a.cfg.RASPMode = string(envelope.Policy.Mode)
	a.cfgMu.Unlock()
	a.setRuntimePreventionEnabled(envelope.Policy.Mode == shared.ModeMonitor)
	if err := a.rotateRASPBridgeToken(); err != nil {
		return err
	}
	return nil
}

func (a *Agent) acknowledgePendingRASPPolicy() error {
	a.cfgMu.RLock()
	envelope := a.raspPolicyEnvelope
	a.cfgMu.RUnlock()
	requestBody, err := json.Marshal(map[string]interface{}{
		"agent_id": a.agentID, "agent_key": a.agentKey,
		"ack_policy_version": envelope.Policy.Version, "ack_policy_signature": envelope.Signature,
		"capabilities": a.capabilityModel(),
	})
	if err != nil {
		return fmt.Errorf("marshal policy ACK: %w", err)
	}
	responseBody, err := httpPostAgent(a.cfg.API+"/api/v1/agent/config", requestBody, a.agentID, a.agentKey)
	if err != nil {
		return fmt.Errorf("send policy ACK: %w", err)
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			Policy shared.SignedPolicy `json:"rasp_policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return fmt.Errorf("parse policy ACK: %w", err)
	}
	if response.Code != 0 || !reflect.DeepEqual(response.Data.Policy, envelope) {
		return errAgentPolicyACK
	}
	if err := a.activateAcknowledgedRASPPolicy(envelope); err != nil {
		return err
	}
	a.startManagedCollectors()
	return nil
}

func loadPolicyRoot(path string) (ed25519.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read RASP policy root: %w", err)
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errAgentPolicySignature
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errAgentPolicySignature
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errAgentPolicySignature
	}
	return publicKey, nil
}

func agentSelected(agentIDs []string, agentID string) bool {
	if len(agentIDs) == 0 {
		return true
	}
	for _, selected := range agentIDs {
		if selected == agentID {
			return true
		}
	}
	return false
}

func agentLanguageSelected(selectors, capabilities []shared.Language) bool {
	if len(selectors) == 0 {
		return true
	}
	for _, selected := range selectors {
		for _, capability := range capabilities {
			if selected == capability {
				return true
			}
		}
	}
	return false
}

func policyRootFingerprint(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}

func (a *Agent) policyACKSnapshot() (uint64, string) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.ackPolicyVersion, a.ackPolicySignature
}
