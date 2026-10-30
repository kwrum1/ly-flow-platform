package main

import (
	"testing"

	"github.com/lyflow/ly-flow-platform/server/models"
)

func TestAgentRecordKind(t *testing.T) {
	tests := []struct {
		name  string
		agent *models.Agent
		want  string
	}{
		{name: "managed agent", agent: &models.Agent{AgentVersion: "v2.0.0", AgentKey: "key"}, want: "agent"},
		{name: "legacy lyprobe", agent: &models.Agent{AgentVersion: "lyprobe-1.0.0"}, want: "sensor"},
		{name: "local mirror key", agent: &models.Agent{AgentVersion: "v2.0.0", AgentKey: "local-mirror"}, want: "sensor"},
		{name: "nil", agent: nil, want: "agent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := agentRecordKind(test.agent); got != test.want {
				t.Fatalf("agentRecordKind()=%q, want %q", got, test.want)
			}
		})
	}
}
