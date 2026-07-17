package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func TestRuntimeControlHealth_reports_fail_policy_limits_and_watchdog(t *testing.T) {
	// Given
	health := newRuntimeControlHealth("agent-runtime", agentRuntimeLimits(), time.Now)

	// When
	snapshot := health.Snapshot()

	// Then
	if snapshot.SchemaVersion != controlHealthSchemaVersion || snapshot.Status != controlHealthHealthy {
		t.Fatalf("unexpected runtime health: %+v", snapshot)
	}
	if snapshot.FailPolicy.Observation != failOpen || snapshot.FailPolicy.Integrity != failClosed || snapshot.FailPolicy.Authorization != failClosed {
		t.Fatalf("unexpected fail policy: %+v", snapshot.FailPolicy)
	}
	if snapshot.Limits.QueueCapacity <= 0 || snapshot.Limits.ReadBytes <= 0 || snapshot.Limits.CPUBudget <= 0 || snapshot.Limits.MemoryBytes <= 0 || snapshot.Limits.RestartBudget <= 0 {
		t.Fatalf("runtime limits are not bounded: %+v", snapshot.Limits)
	}
}

func TestNewAgent_initializes_runtime_health(t *testing.T) {
	// Given / When
	agent := NewAgent(&Config{})
	defer agent.cancel()

	// Then
	snapshot := agent.runtimeHealth.Snapshot()
	if snapshot.Runtime != "agent-runtime" || snapshot.WatchdogAt.IsZero() || snapshot.PreventionEnabled {
		t.Fatalf("agent runtime health was not initialized: %+v", snapshot)
	}
}

func TestRuntimeControlHealth_fail_open_outage_preserves_enabled_policy_mode(t *testing.T) {
	// Given
	health := newRuntimeControlHealth("agent-runtime", agentRuntimeLimits(), time.Now)
	health.setPreventionEnabled(true)

	// When
	snapshot := health.Degrade("observation_delivery_unavailable", false)

	// Then
	if snapshot.Status != controlHealthDegraded || !snapshot.PreventionEnabled {
		t.Fatalf("fail-open outage changed enabled policy mode: %+v", snapshot)
	}
}

func TestRuntimeControlHealth_matches_shared_canonical_fixture_bytes(t *testing.T) {
	// Given
	fixed := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	health := newRuntimeControlHealth("fixture-runtime", agentRuntimeLimits(), func() time.Time { return fixed })
	health.mu.Lock()
	health.status = controlHealthDegraded
	health.reason = "control_health_delivery_unavailable"
	health.preventionActive = true
	health.restartCount = 2
	health.publication = controlHealthPublicationSnapshot{Status: controlHealthDegraded, RetryCount: 3, LastError: "fixture publication unavailable"}
	health.mu.Unlock()
	want, err := os.ReadFile(filepath.Join("..", "..", "contracts", "control-health", "v1", "fixture.json"))
	if err != nil {
		t.Fatalf("read canonical control-health fixture: %v", err)
	}

	// When
	got, err := json.Marshal(health.Snapshot())
	if err != nil {
		t.Fatalf("marshal canonical control health: %v", err)
	}

	// Then
	if !bytes.Equal(got, bytes.TrimSpace(want)) {
		t.Fatalf("agent fixture mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestRestartBudget_rejects_restart_loop_after_budget(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	budget := newRestartBudget(2, time.Minute, func() time.Time { return now })

	// When
	first := budget.Allow()
	second := budget.Allow()
	third := budget.Allow()

	// Then
	if !first || !second || third || budget.Count() != 2 {
		t.Fatalf("restart budget result first=%v second=%v third=%v count=%d", first, second, third, budget.Count())
	}
}

func TestRuntimeControlHealth_restart_budget_exhaustion_fails_closed(t *testing.T) {
	// Given
	limits := agentRuntimeLimits()
	limits.RestartBudget = 1
	health := newRuntimeControlHealth("agent-runtime", limits, time.Now)

	// When
	first := health.RecordWatchdogRestart()
	second := health.RecordWatchdogRestart()

	// Then
	if !first || second {
		t.Fatalf("restart decisions first=%v second=%v", first, second)
	}
	snapshot := health.Snapshot()
	if snapshot.Status != controlHealthDegraded || snapshot.Reason != "restart_budget_exhausted" || snapshot.PreventionEnabled {
		t.Fatalf("restart exhaustion did not fail closed: %+v", snapshot)
	}
}

func TestRuntimeControlHealth_stale_watchdog_degrades_observation_fail_open(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	health := newRuntimeControlHealth("agent-runtime", agentRuntimeLimits(), func() time.Time { return now })
	health.setPreventionEnabled(true)
	now = now.Add(time.Minute)

	// When
	snapshot := health.CheckWatchdog(30 * time.Second)

	// Then
	if snapshot.Status != controlHealthDegraded || snapshot.Reason != "watchdog_stale" || !snapshot.PreventionEnabled {
		t.Fatalf("stale observation watchdog did not fail open: %+v", snapshot)
	}
}

func TestConsumeJSONLineAlertFile_enforces_read_and_memory_limits(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "oversized.jsonl")
	line := append([]byte(`{"message":"`), bytes.Repeat([]byte("a"), agentRuntimeLimits().MemoryBytes)...)
	line = append(line, []byte(`"}`+"\n")...)
	if err := os.WriteFile(path, line, 0o600); err != nil {
		t.Fatalf("write oversized fixture: %v", err)
	}
	agent := NewAgent(&Config{})

	// When
	_, err := agent.consumeJSONLineAlertFile(EngineWazuh, path, 0, func(map[string]interface{}, contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		return contracts.ComponentAlert{}, false, nil
	})

	// Then
	if !errors.Is(err, errRuntimeReadLimit) {
		t.Fatalf("oversized runtime input error = %v, want errRuntimeReadLimit", err)
	}
}

func TestRuntimeBudget_stops_work_after_cpu_budget(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		now = now.Add(60 * time.Millisecond)
		return now
	}
	budget := newRuntimeBudget(RuntimeLimits{CPUBudget: 100 * time.Millisecond}, clock)

	// When
	first := budget.Allow(context.Background(), 1)
	second := budget.Allow(context.Background(), 1)

	// Then
	if !first || second {
		t.Fatalf("CPU budget result first=%v second=%v", first, second)
	}
}
