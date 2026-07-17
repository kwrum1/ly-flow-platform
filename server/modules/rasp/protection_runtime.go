package rasp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (manager *ProtectionManager) syncLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-manager.ctx.Done():
			return
		case <-ticker.C:
			manager.syncAgentsToRedis()
		}
	}
}

func (manager *ProtectionManager) blockCleanLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-manager.ctx.Done():
			return
		case <-ticker.C:
			manager.cleanOldBlocks()
		}
	}
}

func (manager *ProtectionManager) cleanOldBlocks() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	cutoff := time.Now().Add(-time.Hour)
	for _, agent := range manager.agents {
		clean := make([]BlockRecord, 0, len(agent.Stats.RecentBlocks))
		for _, block := range agent.Stats.RecentBlocks {
			if block.Timestamp.After(cutoff) {
				clean = append(clean, block)
			}
		}
		agent.Stats.RecentBlocks = clean
	}
}

func (manager *ProtectionManager) loadAgents() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	ctx := context.Background()
	keys, err := manager.redis.Keys(ctx, "rasp:protection:*").Result()
	if err != nil {
		return
	}
	for _, key := range keys {
		data, err := manager.redis.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var agent AgentProtection
		if err := json.Unmarshal([]byte(data), &agent); err != nil {
			continue
		}
		agent.BlockMode = false
		agentID := key[len("rasp:protection:"):]
		manager.agents[agentID] = &agent
	}
}

func (manager *ProtectionManager) saveAgent(agent *AgentProtection) error {
	agent.BlockMode = false
	data, err := json.Marshal(agent)
	if err != nil {
		return fmt.Errorf("marshal RASP protection state: %w", err)
	}
	key := fmt.Sprintf("rasp:protection:%s", agent.AgentID)
	return manager.redis.Set(context.Background(), key, data, 0).Err()
}

func (manager *ProtectionManager) syncAgentsToRedis() {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	for agentID, agent := range manager.agents {
		data, err := json.Marshal(agent)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("rasp:protection:%s", agentID)
		_ = manager.redis.Set(context.Background(), key, data, 0).Err()
	}
}
