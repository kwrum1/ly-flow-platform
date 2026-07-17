package rasp

import (
	"encoding/json"
	"fmt"
	"time"
)

type ProtectionCommand struct {
	Type            string          `json:"type"`
	AgentID         string          `json:"agent_id"`
	TargetID        string          `json:"target_id"`
	Action          string          `json:"action"`
	BlockMode       bool            `json:"block_mode"`
	BlockType       string          `json:"block_type"`
	RuleID          int             `json:"rule_id"`
	Rule            json.RawMessage `json:"rule"`
	PolicyVersion   uint64          `json:"policy_version"`
	PolicySignature string          `json:"policy_signature"`
	ACKVersion      uint64          `json:"ack_version"`
	RollbackVersion uint64          `json:"rollback_version"`
}

func (manager *ProtectionManager) PublishCommand(command *ProtectionCommand) error {
	return ErrPolicyLifecycleRequired
}

func (manager *ProtectionManager) SubscribeCommands(agentID string) <-chan *ProtectionCommand {
	commands := make(chan *ProtectionCommand, 100)
	go func() {
		pubsub := manager.redis.Subscribe(manager.ctx, fmt.Sprintf("rasp:commands:%s", agentID))
		defer func() {
			_ = pubsub.Close()
			close(commands)
		}()
		for {
			select {
			case <-manager.ctx.Done():
				return
			default:
				message, err := pubsub.ReceiveMessage(manager.ctx)
				if err != nil {
					if manager.ctx.Err() != nil {
						return
					}
					time.Sleep(time.Second)
					continue
				}
				var command ProtectionCommand
				if err := json.Unmarshal([]byte(message.Payload), &command); err == nil {
					commands <- &command
				}
			}
		}
	}()
	return commands
}
