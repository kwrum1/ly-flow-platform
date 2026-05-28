package rasp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type ProtectionManager struct {
	redis     *redis.Client
	agents    map[string]*AgentProtection
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

type AgentProtection struct {
	AgentID       string                 `json:"agent_id"`
	Hostname      string                 `json:"hostname"`
	Language      string                `json:"language"`
	Enabled       bool                  `json:"enabled"`
	BlockMode    bool                  `json:"block_mode"`
	BlockedTypes  map[string]bool       `json:"blocked_types"`
	Rules        map[int]*ProtectionRule `json:"rules"`
	Stats        *ProtectionStats       `json:"stats"`
	LastUpdate   time.Time              `json:"last_update"`
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
	BlockedCount   int64            `json:"blocked_count"`
	AllowedCount   int64            `json:"allowed_count"`
	ByType        map[string]int64 `json:"by_type"`
	RecentBlocks   []BlockRecord   `json:"recent_blocks"`
}

type BlockRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	EventID     string    `json:"event_id"`
	AttackType  string    `json:"attack_type"`
	Action      string    `json:"action"`
	SourceIP    string    `json:"source_ip"`
}

func NewProtectionManager(redisAddr string) (*ProtectionManager, error) {
	pm := &ProtectionManager{
		agents: make(map[string]*AgentProtection),
	}
	pm.ctx, pm.cancel = context.WithCancel(context.Background())

	pm.redis = redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pm.redis.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis连接失败: %w", err)
	}

	pm.loadAgents()

	return pm, nil
}

func (pm *ProtectionManager) Start() {
	go pm.syncLoop()
	go pm.blockCleanLoop()
}

func (pm *ProtectionManager) Stop() {
	pm.cancel()
	if pm.redis != nil {
		pm.redis.Close()
	}
}

func (pm *ProtectionManager) EnableProtection(agentID string, blockMode bool) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if agent, ok := pm.agents[agentID]; ok {
		agent.BlockMode = blockMode
		agent.Enabled = true
		agent.LastUpdate = time.Now()
		return pm.saveAgent(agent)
	}

	agent := &AgentProtection{
		AgentID:      agentID,
		Enabled:     true,
		BlockMode:   blockMode,
		BlockedTypes: make(map[string]bool),
		Rules:        make(map[int]*ProtectionRule),
		Stats: &ProtectionStats{
			ByType:       make(map[string]int64),
			RecentBlocks:  make([]BlockRecord, 0),
		},
		LastUpdate: time.Now(),
	}
	pm.agents[agentID] = agent
	return pm.saveAgent(agent)
}

func (pm *ProtectionManager) DisableProtection(agentID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if agent, ok := pm.agents[agentID]; ok {
		agent.Enabled = false
		agent.LastUpdate = time.Now()
		return pm.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (pm *ProtectionManager) SetBlockType(agentID, attackType string, blocked bool) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if agent, ok := pm.agents[agentID]; ok {
		agent.BlockedTypes[attackType] = blocked
		agent.LastUpdate = time.Now()
		return pm.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (pm *ProtectionManager) AddRule(agentID string, rule *ProtectionRule) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if agent, ok := pm.agents[agentID]; ok {
		agent.Rules[rule.ID] = rule
		agent.LastUpdate = time.Now()
		return pm.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (pm *ProtectionManager) RemoveRule(agentID string, ruleID int) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if agent, ok := pm.agents[agentID]; ok {
		delete(agent.Rules, ruleID)
		agent.LastUpdate = time.Now()
		return pm.saveAgent(agent)
	}
	return fmt.Errorf("Agent不存在: %s", agentID)
}

func (pm *ProtectionManager) GetAgentProtection(agentID string) (*AgentProtection, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if agent, ok := pm.agents[agentID]; ok {
		return agent, nil
	}
	return nil, fmt.Errorf("Agent不存在: %s", agentID)
}

func (pm *ProtectionManager) ListAgents() []*AgentProtection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	agents := make([]*AgentProtection, 0, len(pm.agents))
	for _, agent := range pm.agents {
		agents = append(agents, agent)
	}
	return agents
}

func (pm *ProtectionManager) ShouldBlock(agentID, attackType string) (bool, string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	agent, ok := pm.agents[agentID]
	if !ok || !agent.Enabled {
		return false, "agent_not_protected"
	}

	if !agent.BlockMode {
		return false, "block_mode_disabled"
	}

	if blocked, exists := agent.BlockedTypes[attackType]; exists && blocked {
		return true, "type_blocked"
	}

	for _, rule := range agent.Rules {
		if rule.Type == attackType && rule.Enabled && rule.Action == "block" {
			return true, fmt.Sprintf("rule_%d", rule.ID)
		}
	}

	return false, "not_blocked"
}

func (pm *ProtectionManager) RecordBlock(agentID string, event *RASPEvent) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	agent, ok := pm.agents[agentID]
	if !ok {
		return
	}

	agent.Stats.BlockedCount++
	agent.Stats.ByType[string(event.AttackType)]++
	agent.Stats.RecentBlocks = append(agent.Stats.RecentBlocks, BlockRecord{
		Timestamp:  event.Timestamp,
		EventID:    event.ID,
		AttackType: string(event.AttackType),
		Action:     "blocked",
		SourceIP:   event.Request.ClientIP,
	})

	if len(agent.Stats.RecentBlocks) > 100 {
		agent.Stats.RecentBlocks = agent.Stats.RecentBlocks[len(agent.Stats.RecentBlocks)-100:]
	}

	pm.saveAgent(agent)
}

func (pm *ProtectionManager) RecordAllow(agentID string, event *RASPEvent) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	agent, ok := pm.agents[agentID]
	if !ok {
		return
	}
	agent.Stats.AllowedCount++
}

func (pm *ProtectionManager) syncLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.syncAgentsToRedis()
		}
	}
}

func (pm *ProtectionManager) blockCleanLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.cleanOldBlocks()
		}
	}
}

func (pm *ProtectionManager) cleanOldBlocks() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for _, agent := range pm.agents {
		clean := make([]BlockRecord, 0)
		for _, block := range agent.Stats.RecentBlocks {
			if block.Timestamp.After(cutoff) {
				clean = append(clean, block)
			}
		}
		agent.Stats.RecentBlocks = clean
	}
}

func (pm *ProtectionManager) loadAgents() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	ctx := context.Background()
	keys, err := pm.redis.Keys(ctx, "rasp:protection:*").Result()
	if err != nil {
		return
	}

	for _, key := range keys {
		data, err := pm.redis.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var agent AgentProtection
		if err := json.Unmarshal([]byte(data), &agent); err != nil {
			continue
		}

		agentID := key[len("rasp:protection:"):]
		pm.agents[agentID] = &agent
	}
}

func (pm *ProtectionManager) saveAgent(agent *AgentProtection) error {
	data, err := json.Marshal(agent)
	if err != nil {
		return err
	}

	ctx := context.Background()
	key := fmt.Sprintf("rasp:protection:%s", agent.AgentID)
	return pm.redis.Set(ctx, key, data, 0).Err()
}

func (pm *ProtectionManager) syncAgentsToRedis() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	ctx := context.Background()
	for agentID, agent := range pm.agents {
		data, _ := json.Marshal(agent)
		key := fmt.Sprintf("rasp:protection:%s", agentID)
		pm.redis.Set(ctx, key, data, 0)
	}
}

type ProtectionCommand struct {
	Type      string      `json:"type"`
	AgentID   string      `json:"agent_id"`
	TargetID  string      `json:"target_id"`
	Action    string      `json:"action"`
	BlockMode bool        `json:"block_mode"`
	BlockType string      `json:"block_type"`
	RuleID    int         `json:"rule_id"`
	Rule      interface{} `json:"rule"`
}

func (pm *ProtectionManager) PublishCommand(cmd *ProtectionCommand) error {
	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()
	channel := fmt.Sprintf("rasp:commands:%s", cmd.AgentID)
	return pm.redis.Publish(ctx, channel, data).Err()
}

func (pm *ProtectionManager) SubscribeCommands(agentID string) <-chan *ProtectionCommand {
	ch := make(chan *ProtectionCommand, 100)

	go func() {
		ctx := context.Background()
		channel := fmt.Sprintf("rasp:commands:%s", agentID)
		pubsub := pm.redis.Subscribe(ctx, channel)

		for {
			select {
			case <-pm.ctx.Done():
				pubsub.Close()
				close(ch)
				return
			default:
				msg, err := pubsub.ReceiveMessage(ctx)
				if err != nil {
					time.Sleep(time.Second)
					continue
				}

				var cmd ProtectionCommand
				if err := json.Unmarshal([]byte(msg.Payload), &cmd); err != nil {
					continue
				}
				ch <- &cmd
			}
		}
	}()

	return ch
}
