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
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	agent, ok := manager.agents[agentID]
	if !ok || !agent.Enabled {
		return false, "agent_not_protected"
	}
	return false, "production_block_disabled"
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
	}
}
