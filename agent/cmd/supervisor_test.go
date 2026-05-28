package main

import (
	"context"
	"errors"
	"testing"
)

type failingEngineSupervisor struct{}

func (f failingEngineSupervisor) Name() EngineName { return EngineWazuh }

func (f failingEngineSupervisor) Apply(context.Context, EngineDesiredState) error {
	return errors.New("apply failed")
}

func (f failingEngineSupervisor) Status(context.Context) EngineStatus {
	return EngineStatus{Name: EngineWazuh, Installed: true}
}

func TestEngineRegistryApply(t *testing.T) {
	registry := NewEngineRegistry(newStaticEngineSupervisor(EngineSuricata))
	statuses := registry.Apply(context.Background(), []EngineDesiredState{{Name: EngineSuricata, Enabled: true, RulePackVersion: "et-open-1"}})
	status := statuses[EngineSuricata]
	if !status.Running || status.RulePackVersion != "et-open-1" || status.LastError != "" {
		t.Fatalf("suricata status mismatch: %+v", status)
	}
}

func TestEngineRegistryReportsMissingSupervisor(t *testing.T) {
	registry := NewEngineRegistry()
	statuses := registry.Apply(context.Background(), []EngineDesiredState{{Name: EngineYARA, Enabled: true}})
	status := statuses[EngineYARA]
	if status.LastError == "" {
		t.Fatalf("missing supervisor status did not include error: %+v", status)
	}
}

func TestEngineRegistryPreservesApplyError(t *testing.T) {
	registry := NewEngineRegistry(failingEngineSupervisor{})
	statuses := registry.Apply(context.Background(), []EngineDesiredState{{Name: EngineWazuh, Enabled: true}})
	status := statuses[EngineWazuh]
	if status.LastError != "apply failed" {
		t.Fatalf("LastError = %q, want apply failed", status.LastError)
	}
}

func TestNewAgentRegistersV2EngineSupervisors(t *testing.T) {
	agent := NewAgent(&Config{})
	statuses := agent.engines.Snapshot(context.Background())
	for _, name := range []EngineName{EngineSuricata, EngineWazuh, EngineYARA, EngineRASP} {
		if _, ok := statuses[name]; !ok {
			t.Fatalf("engine %s not registered in snapshot: %+v", name, statuses)
		}
	}
}
