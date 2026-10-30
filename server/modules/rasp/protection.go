package rasp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/internal/redisconfig"
	"github.com/redis/go-redis/v9"
)

var ErrPolicyLifecycleRequired = errors.New("RASP protection requires a signed monitor-first policy lifecycle")

type ProtectionManager struct {
	redis  *redis.Client
	agents map[string]*AgentProtection
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc

	policyMu         sync.RWMutex
	policy           BlockPolicy
	dryRunWouldBlock int64
	policyUpdatedAt  time.Time
}

type AgentProtection struct {
	AgentID      string                  `json:"agent_id"`
	Hostname     string                  `json:"hostname"`
	Language     string                  `json:"language"`
	Enabled      bool                    `json:"enabled"`
	BlockMode    bool                    `json:"block_mode"`
	BlockedTypes map[string]bool         `json:"blocked_types"`
	Rules        map[int]*ProtectionRule `json:"rules"`
	Stats        *ProtectionStats        `json:"stats"`
	LastUpdate   time.Time               `json:"last_update"`
	LastEventAt  time.Time               `json:"last_event_at,omitempty"`
}

type ProtectionRule struct {
	ID        int    `json:"id"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	Enabled   bool   `json:"enabled"`
	Timeout   int    `json:"timeout"`
	Threshold int    `json:"threshold"`
}

type ProtectionStats struct {
	BlockedCount int64            `json:"blocked_count"`
	AllowedCount int64            `json:"allowed_count"`
	ByType       map[string]int64 `json:"by_type"`
	RecentBlocks []BlockRecord    `json:"recent_blocks"`
}

type BlockRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	EventID    string    `json:"event_id"`
	AttackType string    `json:"attack_type"`
	Action     string    `json:"action"`
	SourceIP   string    `json:"source_ip"`
}

func NewProtectionManager(redisAddr string) (*ProtectionManager, error) {
	manager := &ProtectionManager{agents: make(map[string]*AgentProtection)}
	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	manager.redis = redis.NewClient(redisconfig.Options(redisAddr, 0))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.redis.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis连接失败: %w", err)
	}
	manager.loadAgents()
	return manager, nil
}

func (manager *ProtectionManager) Start() {
	go manager.syncLoop()
	go manager.blockCleanLoop()
}

func (manager *ProtectionManager) Stop() {
	manager.cancel()
	if manager.redis != nil {
		_ = manager.redis.Close()
	}
}

func (manager *ProtectionManager) EnableProtection(agentID string, blockMode bool) error {
	if blockMode {
		return ErrPolicyLifecycleRequired
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if agent, ok := manager.agents[agentID]; ok {
		agent.BlockMode = false
		agent.Enabled = true
		agent.LastUpdate = time.Now()
		return manager.saveAgent(agent)
	}
	agent := &AgentProtection{
		AgentID: agentID, Enabled: true, BlockedTypes: make(map[string]bool), Rules: make(map[int]*ProtectionRule),
		Stats: &ProtectionStats{ByType: make(map[string]int64), RecentBlocks: make([]BlockRecord, 0)}, LastUpdate: time.Now(),
	}
	manager.agents[agentID] = agent
	return manager.saveAgent(agent)
}

func (manager *ProtectionManager) DisableProtection(agentID string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if agent, ok := manager.agents[agentID]; ok {
		agent.Enabled = false
		agent.LastUpdate = time.Now()
		return manager.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (manager *ProtectionManager) SetBlockType(agentID, attackType string, blocked bool) error {
	if blocked {
		return ErrPolicyLifecycleRequired
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if agent, ok := manager.agents[agentID]; ok {
		agent.BlockedTypes[attackType] = false
		agent.LastUpdate = time.Now()
		return manager.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (manager *ProtectionManager) AddRule(agentID string, rule *ProtectionRule) error {
	if rule.Action == "block" {
		return ErrPolicyLifecycleRequired
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if agent, ok := manager.agents[agentID]; ok {
		agent.Rules[rule.ID] = rule
		agent.LastUpdate = time.Now()
		return manager.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (manager *ProtectionManager) RemoveRule(agentID string, ruleID int) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if agent, ok := manager.agents[agentID]; ok {
		delete(agent.Rules, ruleID)
		agent.LastUpdate = time.Now()
		return manager.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (manager *ProtectionManager) GetAgentProtection(agentID string) (*AgentProtection, error) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if agent, ok := manager.agents[agentID]; ok {
		return agent, nil
	}
	return nil, fmt.Errorf("Agent不存在: %s", agentID)
}

func (manager *ProtectionManager) ListAgents() []*AgentProtection {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	agents := make([]*AgentProtection, 0, len(manager.agents))
	for _, agent := range manager.agents {
		agents = append(agents, agent)
	}
	return agents
}

func (manager *ProtectionManager) ShouldBlock(agentID, _ string) (bool, string) {
	decision := manager.EvaluateBlock(agentID, "")
	return decision.Block, decision.Reason
}

// EvaluateBlock runs the fail-safe policy for one request.
func (manager *ProtectionManager) EvaluateBlock(agentID, _ string) BlockDecision {
	manager.mu.RLock()
	agent, ok := manager.agents[agentID]
	enabled := ok && agent != nil && agent.Enabled
	manager.mu.RUnlock()

	manager.policyMu.RLock()
	policy := manager.policy
	manager.policyMu.RUnlock()

	decision := policy.Decide(time.Now().UTC(), enabled)
	if decision.WouldBlock && !decision.Block {
		manager.policyMu.Lock()
		manager.dryRunWouldBlock++
		manager.policyMu.Unlock()
	}
	return decision
}

// SetBlockPolicy installs the fail-safe policy. Callers must already hold a
// signed policy; this function itself never promotes monitor to enforce.
func (manager *ProtectionManager) SetBlockPolicy(policy BlockPolicy) {
	policy.Mode = normalizeBlockMode(policy.Mode)
	manager.policyMu.Lock()
	manager.policy = policy
	manager.policyUpdatedAt = time.Now().UTC()
	manager.policyMu.Unlock()
}

// SetEmergencyStop is the runtime kill switch. It is immediate and does not
// require a policy update; every subsequent decision fails safe.
func (manager *ProtectionManager) SetEmergencyStop(stop bool) {
	manager.policyMu.Lock()
	manager.policy.EmergencyStop = stop
	manager.policyUpdatedAt = time.Now().UTC()
	manager.policyMu.Unlock()
}

// BlockPolicySnapshot returns the policy plus dry-run counters for the API.
func (manager *ProtectionManager) BlockPolicySnapshot() map[string]interface{} {
	manager.policyMu.RLock()
	defer manager.policyMu.RUnlock()
	snapshot := map[string]interface{}{
		"mode":                 manager.policy.Mode,
		"policy_signed":        manager.policy.PolicySigned,
		"emergency_stop":       manager.policy.EmergencyStop,
		"dry_run_would_block":  manager.dryRunWouldBlock,
		"updated_at":           manager.policyUpdatedAt,
		"fail_safe_on_unknown": true,
	}
	if !manager.policy.PolicyExpiresAt.IsZero() {
		snapshot["policy_expires_at"] = manager.policy.PolicyExpiresAt.UTC().Format(time.RFC3339)
	}
	return snapshot
}

// ProtectionStates resolves the five-state lifecycle for every known agent.
func (manager *ProtectionManager) ProtectionStates() map[string]ProtectionState {
	manager.mu.RLock()
	agents := make([]*AgentProtection, 0, len(manager.agents))
	for _, agent := range manager.agents {
		agents = append(agents, agent)
	}
	manager.mu.RUnlock()

	manager.policyMu.RLock()
	policy := manager.policy
	manager.policyMu.RUnlock()

	now := time.Now().UTC()
	states := make(map[string]ProtectionState, len(agents))
	for _, agent := range agents {
		eventsObserved := agent.Stats != nil && (agent.Stats.AllowedCount+agent.Stats.BlockedCount) > 0
		if !agent.LastEventAt.IsZero() {
			eventsObserved = true
		}
		states[agent.AgentID] = ResolveProtectionState(StateFacts{
			AgentPresent:       true,
			ProbeReported:      !agent.LastUpdate.IsZero(),
			EventsObserved:     eventsObserved,
			DetectionsObserved: agent.Stats != nil && agent.Stats.BlockedCount > 0,
			ProtectionEnabled:  agent.Enabled,
			BlockMode:          agent.BlockMode,
			PolicySigned:       policy.PolicySigned,
			PolicyExpiresAt:    policy.PolicyExpiresAt,
			EmergencyStop:      policy.EmergencyStop,
			LastEventAt:        agent.LastEventAt,
			Now:                now,
		})
	}
	return states
}

func (manager *ProtectionManager) RecordBlock(agentID string, event *RASPEvent) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	agent, ok := manager.agents[agentID]
	if !ok {
		return
	}
	agent.Stats.BlockedCount++
	agent.Stats.ByType[string(event.AttackType)]++
	agent.LastEventAt = event.Timestamp
	if agent.LastEventAt.IsZero() {
		agent.LastEventAt = time.Now().UTC()
	}
	agent.Stats.RecentBlocks = append(agent.Stats.RecentBlocks, BlockRecord{
		Timestamp: event.Timestamp, EventID: event.ID, AttackType: string(event.AttackType), Action: "blocked", SourceIP: event.Request.ClientIP,
	})
	if len(agent.Stats.RecentBlocks) > 100 {
		agent.Stats.RecentBlocks = agent.Stats.RecentBlocks[len(agent.Stats.RecentBlocks)-100:]
	}
	_ = manager.saveAgent(agent)
}

func (manager *ProtectionManager) RecordAllow(agentID string, _ *RASPEvent) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if agent, ok := manager.agents[agentID]; ok {
		agent.Stats.AllowedCount++
		agent.LastEventAt = time.Now().UTC()
	}
}
