package main

import (
	"context"
	"testing"
)

func TestSuricataSupervisorReportsMissingExecutable(t *testing.T) {
	supervisor := newExternalEngineSupervisor(EngineSuricata, "lyflow-missing-suricata-binary", "/tmp/lyflow-missing-eve.json")

	if err := supervisor.Apply(context.Background(), EngineDesiredState{
		Name:            EngineSuricata,
		Enabled:         true,
		RulePackVersion: "et-open-active",
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	status := supervisor.Status(context.Background())
	if status.Installed || status.Running {
		t.Fatalf("missing executable must not look installed/running: %#v", status)
	}
	if status.Version != "" {
		t.Fatalf("missing executable must not report a version: %#v", status)
	}
	if status.RulePackVersion != "" {
		t.Fatalf("missing executable must not report a rule pack: %#v", status)
	}
	if status.LastError == "" {
		t.Fatalf("missing executable must explain itself: %#v", status)
	}
}

func TestDisabledEngineClearsPreviousVersion(t *testing.T) {
	supervisor := newExternalEngineSupervisor(EngineSuricata, "lyflow-missing-suricata-binary", "/tmp/lyflow-missing-eve.json")
	_ = supervisor.Apply(context.Background(), EngineDesiredState{Name: EngineSuricata, Enabled: true, RulePackVersion: "et-open-active"})
	_ = supervisor.Apply(context.Background(), EngineDesiredState{Name: EngineSuricata, Enabled: false})

	status := supervisor.Status(context.Background())
	if status.Running || status.Version != "" || status.RulePackVersion != "" {
		t.Fatalf("disabled engine kept stale state: %#v", status)
	}
}

func TestRASPAdapterRunsInProcess(t *testing.T) {
	supervisor := newRASPSupervisor()
	if err := supervisor.Apply(context.Background(), EngineDesiredState{Name: EngineRASP, Enabled: true, RulePackVersion: "rasp-active"}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	status := supervisor.Status(context.Background())
	if !status.Installed || !status.Running || status.Version != "ly-agent-adapter" {
		t.Fatalf("in-process adapter must report installed/running: %#v", status)
	}
	if status.RulePackVersion != "rasp-active" {
		t.Fatalf("adapter lost rule pack: %#v", status)
	}
}
