package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

const (
	raspBridgeEventsPath       = "/v1/rasp/events"
	raspBridgeConfigPath       = "/v1/rasp/config"
	raspBridgeHealthPath       = "/v1/rasp/health"
	raspBridgeTokenHeader      = "X-Ly-RASP-Token"
	raspBridgeAgentHeader      = "X-Lyflow-Agent-ID"
	raspBridgeDefaultQueueSize = 128
	raspBridgeTokenOverlap     = 2 * time.Minute
)

type raspBridgeConfigResponse struct {
	SchemaVersion   string                 `json:"schema_version"`
	AgentID         string                 `json:"agent_id"`
	PolicyID        string                 `json:"policy_id"`
	PolicyVersion   uint64                 `json:"policy_version"`
	PolicyMode      shared.Mode            `json:"policy_mode"`
	ExpiresAt       time.Time              `json:"expires_at"`
	BridgeToken     string                 `json:"bridge_token"`
	Limits          raspBridgeConfigLimits `json:"limits"`
	ConfigSignature string                 `json:"config_signature"`
	Delivery        raspBridgeHealth       `json:"delivery"`
}

type raspBridgeConfigLimits struct {
	QueueCapacity int   `json:"queue_capacity"`
	ReadBytes     int   `json:"read_bytes"`
	CPUBudgetMS   int64 `json:"cpu_budget_ms"`
	MemoryBytes   int   `json:"memory_bytes"`
	RestartBudget int   `json:"restart_budget"`
}

func (bridge *raspBridgeRuntime) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(raspBridgeEventsPath, bridge.handleEvent)
	mux.HandleFunc(raspBridgeConfigPath, bridge.handleConfig)
	mux.HandleFunc(raspBridgeHealthPath, bridge.handleHealth)
	return mux
}

func (bridge *raspBridgeRuntime) authenticate(w http.ResponseWriter, r *http.Request) bool {
	if !bridge.tokens.Authenticate(r.Header.Get(raspBridgeTokenHeader)) {
		if err := bridge.agent.propagateControlHealth(bridge.agent.runtimeHealth.Degrade("authorization_failed", true)); err != nil {
			http.Error(w, "control-health publication failed", http.StatusInternalServerError)
			return false
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if r.Header.Get(raspBridgeAgentHeader) != bridge.agent.agentID {
		if err := bridge.agent.propagateControlHealth(bridge.agent.runtimeHealth.Degrade("authorization_failed", true)); err != nil {
			http.Error(w, "control-health publication failed", http.StatusInternalServerError)
			return false
		}
		http.Error(w, "agent binding mismatch", http.StatusForbidden)
		return false
	}
	return true
}

func (bridge *raspBridgeRuntime) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !bridge.authenticate(w, r) {
		return
	}
	now := bridge.now().UTC()
	bridge.agent.enforceRASPPolicyExpiry(now)
	binding, active := bridge.agent.raspBridgePolicyBinding()
	if !active {
		http.Error(w, "RASP policy inactive", http.StatusServiceUnavailable)
		return
	}
	budget := newRuntimeBudget(bridge.limits, bridge.now)
	request, bytesRead, err := decodeRASPBridgeEvent(w, r, bridge.maxEventBytes())
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid RASP event schema", http.StatusBadRequest)
		return
	}
	if !budget.Allow(r.Context(), bytesRead) {
		bridge.rejected.Add(1)
		if err := bridge.agent.publishControlHealth(bridge.agent.runtimeHealth.Degrade("cpu_or_read_budget_exceeded", false)); err != nil {
			http.Error(w, "control-health publication failed", http.StatusInternalServerError)
			return
		}
		http.Error(w, "RASP event resource budget exceeded", http.StatusTooManyRequests)
		return
	}
	if err := request.validate(binding); err != nil {
		if errors.Is(err, errRASPBridgeBinding) {
			http.Error(w, "RASP event binding mismatch", http.StatusConflict)
			return
		}
		http.Error(w, "invalid RASP event schema", http.StatusBadRequest)
		return
	}
	if !bridge.agent.allowRASPEvent(now) {
		bridge.rejected.Add(1)
		http.Error(w, "RASP event rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	item, err := request.delivery(binding, now)
	if err != nil {
		http.Error(w, "invalid canonical RASP event", http.StatusBadRequest)
		return
	}
	enqueued, err := bridge.enqueue(item)
	if err != nil {
		http.Error(w, "RASP event rejection reporting failed", http.StatusInternalServerError)
		return
	}
	if !enqueued {
		http.Error(w, "RASP event queue full; fallback persisted", http.StatusTooManyRequests)
		return
	}
	if err := encodeRASPBridgeJSON(w, http.StatusAccepted, map[string]interface{}{"code": 0, "message": "accepted", "event_uid": item.telemetry.ID}); err != nil {
		bridge.setLastError(err)
	}
}

func (bridge *raspBridgeRuntime) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !bridge.authenticate(w, r) {
		return
	}
	binding, active := bridge.agent.raspBridgePolicyBinding()
	if !active {
		http.Error(w, "RASP policy inactive", http.StatusServiceUnavailable)
		return
	}
	response := raspBridgeConfigResponse{
		SchemaVersion: "lyflow.rasp_bridge_config.v1", AgentID: binding.AgentID, PolicyID: binding.PolicyID,
		PolicyVersion: binding.Version, PolicyMode: binding.Mode, ExpiresAt: binding.ExpiresAt,
		BridgeToken: bridge.tokens.Current(), Limits: bridgeConfigLimits(), Delivery: bridge.Health(),
	}
	response.ConfigSignature = signRASPBridgeConfig(response, r.Header.Get(raspBridgeTokenHeader))
	if err := encodeRASPBridgeJSON(w, http.StatusOK, response); err != nil {
		bridge.setLastError(err)
	}
}

func bridgeConfigLimits() raspBridgeConfigLimits {
	limits := agentRuntimeLimits()
	return raspBridgeConfigLimits{
		QueueCapacity: limits.QueueCapacity, ReadBytes: 64 << 10, CPUBudgetMS: 50,
		MemoryBytes: 1 << 20, RestartBudget: limits.RestartBudget,
	}
}

func (bridge *raspBridgeRuntime) maxEventBytes() int64 {
	limit := bridge.limits.ReadBytes
	if limit <= 0 || bridge.limits.MemoryBytes > 0 && bridge.limits.MemoryBytes < limit {
		limit = bridge.limits.MemoryBytes
	}
	if limit <= 0 {
		limit = raspBridgeMaxBodyBytes
	}
	return int64(limit)
}

func signRASPBridgeConfig(response raspBridgeConfigResponse, secret string) string {
	payload, err := json.Marshal(map[string]interface{}{
		"agent_id": response.AgentID, "bridge_token": response.BridgeToken, "expires_at": response.ExpiresAt,
		"limits": map[string]interface{}{
			"queue_capacity": response.Limits.QueueCapacity, "read_bytes": response.Limits.ReadBytes,
			"cpu_budget_ms": response.Limits.CPUBudgetMS, "memory_bytes": response.Limits.MemoryBytes,
			"restart_budget": response.Limits.RestartBudget,
		},
		"policy_id": response.PolicyID, "policy_mode": response.PolicyMode,
		"policy_version": response.PolicyVersion, "schema_version": response.SchemaVersion,
	})
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *Agent) raspBridgePolicyBinding() (raspBridgePolicyBinding, bool) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	policy := a.raspPolicyEnvelope.Policy
	binding := raspBridgePolicyBinding{
		AgentID: a.agentID, PolicyID: policy.ID, Version: policy.Version, Mode: shared.Mode(a.cfg.RASPMode),
		ExpiresAt: a.raspPolicyExpiresAt, Languages: append([]shared.Language(nil), policy.Selectors.Languages...),
		Signature: a.ackPolicySignature, Acknowledged: a.raspPolicyACKed,
	}
	active := a.cfg.RASPEnabled && binding.Acknowledged && binding.AgentID != "" && binding.PolicyID != "" && binding.Version > 0
	return binding, active
}

func (a *Agent) setRASPBridge(bridge *raspBridgeRuntime) {
	a.raspBridgeMu.Lock()
	a.raspBridge = bridge
	a.raspBridgeMu.Unlock()
}

func (a *Agent) raspBridgeHealthSnapshot() (raspBridgeHealth, bool) {
	a.raspBridgeMu.RLock()
	bridge := a.raspBridge
	a.raspBridgeMu.RUnlock()
	if bridge == nil {
		return raspBridgeHealth{}, false
	}
	return bridge.Health(), true
}

func (a *Agent) rotateRASPBridgeToken() error {
	next, err := generateRASPBridgeToken()
	if err != nil {
		return fmt.Errorf("generate RASP bridge token: %w", err)
	}
	a.raspBridgeMu.RLock()
	bridge := a.raspBridge
	a.raspBridgeMu.RUnlock()
	if bridge != nil {
		if err := bridge.RotateToken(next); err != nil {
			return fmt.Errorf("rotate RASP bridge token: %w", err)
		}
	}
	a.cfgMu.Lock()
	a.cfg.RASPBridgeToken = next
	a.cfgMu.Unlock()
	return nil
}
