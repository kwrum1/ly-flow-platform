package rasp

import (
	"errors"
	"testing"
)

func TestProtectionManager_rejects_legacy_block_paths(t *testing.T) {
	// Given
	manager := &ProtectionManager{agents: map[string]*AgentProtection{}}

	// When
	enableErr := manager.EnableProtection("agent-1", true)
	commandErr := manager.PublishCommand(&ProtectionCommand{AgentID: "agent-1", Action: "block", BlockMode: true})

	// Then
	if !errors.Is(enableErr, ErrPolicyLifecycleRequired) || !errors.Is(commandErr, ErrPolicyLifecycleRequired) {
		t.Fatalf("enable error=%v command error=%v", enableErr, commandErr)
	}
}
