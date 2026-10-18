package stage

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func baseTime() time.Time {
	return time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
}

func event(uid string, stage contracts.AttackStage, source string, at time.Time) Event {
	return Event{EventUID: uid, Stage: stage, Source: source, Confidence: 0.9, EventAt: at}
}

func TestInitialAndSequentialProgression(t *testing.T) {
	var state State
	config := Config{MaxGap: 24 * time.Hour, MinConfidence: 0.5}
	start := baseTime()

	first := state.Apply(event("e1", contracts.StageRecon, "suricata", start), config)
	if !first.Advanced || first.Reason != "initial" || state.Current != contracts.StageRecon {
		t.Fatalf("initial transition: %+v state=%+v", first, state.Snapshot())
	}

	second := state.Apply(event("e2", contracts.StageInitialAccess, "suricata", start.Add(time.Minute)), config)
	if !second.Advanced || state.Current != contracts.StageInitialAccess {
		t.Fatalf("second transition: %+v", second)
	}

	third := state.Apply(event("e3", contracts.StageExecution, "suricata", start.Add(2*time.Minute)), config)
	if !third.Advanced || state.Current != contracts.StageExecution {
		t.Fatalf("third transition: %+v", third)
	}
	if len(state.Snapshot().Reached) != 3 {
		t.Fatalf("reached = %+v", state.Snapshot().Reached)
	}
}

func TestRegressionDoesNotDowngrade(t *testing.T) {
	var state State
	config := Config{}
	start := baseTime()
	state.Apply(event("e1", contracts.StageExecution, "suricata", start), config)
	transition := state.Apply(event("e2", contracts.StageRecon, "suricata", start.Add(time.Minute)), config)
	if transition.Advanced || state.Current != contracts.StageExecution {
		t.Fatalf("regression changed state: %+v", transition)
	}
	if transition.Reason != "regressed" {
		t.Fatalf("reason = %q", transition.Reason)
	}
	if len(state.Snapshot().Evidence) != 2 {
		t.Fatalf("evidence should still be attached: %+v", state.Snapshot().Evidence)
	}
}

func TestSameStageAccumulatesEvidence(t *testing.T) {
	var state State
	config := Config{}
	start := baseTime()
	state.Apply(event("e1", contracts.StageInitialAccess, "suricata", start), config)
	transition := state.Apply(event("e2", contracts.StageInitialAccess, "wazuh", start.Add(time.Minute)), config)
	if transition.Advanced || transition.Reason != "same_stage" {
		t.Fatalf("transition = %+v", transition)
	}
	if len(state.Snapshot().Evidence) != 2 {
		t.Fatalf("evidence = %+v", state.Snapshot().Evidence)
	}
}

func TestRejectsJumpTooLarge(t *testing.T) {
	var state State
	config := Config{MaxJump: 2}
	start := baseTime()
	state.Apply(event("e1", contracts.StageRecon, "suricata", start), config)
	transition := state.Apply(event("e2", contracts.StageLateralMovement, "suricata", start.Add(time.Minute)), config)
	if transition.Advanced || transition.Reason != "jump_too_large" {
		t.Fatalf("transition = %+v", transition)
	}
}

func TestRejectsOutOfWindow(t *testing.T) {
	var state State
	config := Config{MaxGap: 24 * time.Hour}
	start := baseTime()
	state.Apply(event("e1", contracts.StageRecon, "suricata", start), config)
	transition := state.Apply(event("e2", contracts.StageInitialAccess, "suricata", start.Add(25*time.Hour)), config)
	if transition.Advanced || transition.Reason != "out_of_window" {
		t.Fatalf("transition = %+v", transition)
	}
}

func TestRejectsLowConfidence(t *testing.T) {
	var state State
	config := Config{MinConfidence: 0.7}
	start := baseTime()
	state.Apply(event("e1", contracts.StageRecon, "suricata", start), config)
	low := event("e2", contracts.StageInitialAccess, "suricata", start.Add(time.Minute))
	low.Confidence = 0.4
	transition := state.Apply(low, config)
	if transition.Advanced || transition.Reason != "low_confidence" {
		t.Fatalf("transition = %+v", transition)
	}
}

func TestCorroborationGate(t *testing.T) {
	var state State
	config := Config{RequireCorroboration: true}
	start := baseTime()
	state.Apply(event("e1", contracts.StageRecon, "suricata", start), config)

	sameSource := state.Apply(event("e2", contracts.StageInitialAccess, "suricata", start.Add(time.Minute)), config)
	if sameSource.Advanced || sameSource.Reason != "needs_corroboration" {
		t.Fatalf("same-source transition = %+v", sameSource)
	}

	otherSource := state.Apply(event("e3", contracts.StageInitialAccess, "wazuh", start.Add(2*time.Minute)), config)
	if !otherSource.Advanced {
		t.Fatalf("other-source transition = %+v", otherSource)
	}
}

func TestRejectsDuplicateAndUnknown(t *testing.T) {
	var state State
	config := Config{}
	start := baseTime()
	state.Apply(event("e1", contracts.StageRecon, "suricata", start), config)
	if transition := state.Apply(event("e1", contracts.StageExecution, "suricata", start.Add(time.Minute)), config); transition.Reason != "duplicate" {
		t.Fatalf("duplicate transition = %+v", transition)
	}
	if transition := state.Apply(event("e2", contracts.StageUnknown, "suricata", start.Add(time.Minute)), config); transition.Reason != "unknown_stage" {
		t.Fatalf("unknown transition = %+v", transition)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	var state State
	state.Apply(event("e1", contracts.StageRecon, "suricata", baseTime()), Config{})
	snapshot := state.Snapshot()
	snapshot.Reached[0] = contracts.StageImpact
	if state.Snapshot().Reached[0] != contracts.StageRecon {
		t.Fatal("snapshot shares state slice")
	}
}
