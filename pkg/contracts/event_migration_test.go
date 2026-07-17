package contracts

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEventMigrationPhasesAndRollback(t *testing.T) {
	state := NewMigrationState()
	want := []MigrationPhase{PhaseReaderFirst, PhaseDualWrite, PhaseReconcile, PhaseReadSwitch, PhaseObserve}
	for _, phase := range want[1:] {
		if err := state.Advance(phase); err != nil {
			t.Fatalf("advance to %s: %v", phase, err)
		}
	}
	if state.ReadSource() != ReadCanonical || state.WriteMode() != WriteDual {
		t.Fatalf("unexpected observe routing: read=%s write=%s", state.ReadSource(), state.WriteMode())
	}
	if err := state.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if state.Phase() != PhaseReconcile || state.ReadSource() != ReadLegacy {
		t.Fatalf("rollback did not restore legacy read: phase=%s read=%s", state.Phase(), state.ReadSource())
	}
}

func TestEventMigrationRejectsStaleOrSkippedState(t *testing.T) {
	state := NewMigrationState()
	if err := state.Advance(PhaseReconcile); !errors.Is(err, ErrInvalidMigrationTransition) {
		t.Fatalf("skipped phase accepted: %v", err)
	}
	if err := state.Restore(MigrationSnapshot{Phase: "bogus", Revision: 1}); !errors.Is(err, ErrStaleMigrationState) {
		t.Fatalf("invalid persisted phase accepted: %v", err)
	}
	if err := state.Restore(MigrationSnapshot{Phase: PhaseDualWrite, Revision: 1}); !errors.Is(err, ErrStaleMigrationState) {
		t.Fatalf("equal-revision phase replacement accepted: %v", err)
	}
	if err := state.Restore(MigrationSnapshot{Phase: PhaseReconcile, Revision: 3}); !errors.Is(err, ErrStaleMigrationState) {
		t.Fatalf("skipped persisted phase accepted: %v", err)
	}
	if err := state.Restore(MigrationSnapshot{Phase: PhaseDualWrite, Revision: 2}); err != nil {
		t.Fatalf("adjacent persisted phase rejected: %v", err)
	}
	if err := state.Restore(MigrationSnapshot{Phase: PhaseReaderFirst, Revision: 2}); !errors.Is(err, ErrStaleMigrationState) {
		t.Fatalf("equal-revision rollback accepted: %v", err)
	}
}

func TestEventMigrationReconciliationDeterministic(t *testing.T) {
	legacy := []ReconcileRecord{{EventUID: "e-2", Payload: []byte(`{"b":2}`)}, {EventUID: "e-1", Payload: []byte(`{"a":1}`)}}
	canonical := []ReconcileRecord{{EventUID: "e-1", Payload: []byte(`{"a":1}`)}, {EventUID: "e-2", Payload: []byte(`{"b":2}`)}}

	first := Reconcile(legacy, canonical)
	second := Reconcile(legacy, canonical)
	if !first.Match || first.LegacyChecksum != second.LegacyChecksum || first.CanonicalChecksum != second.CanonicalChecksum {
		t.Fatalf("reconciliation was not deterministic: %+v %+v", first, second)
	}
}

func TestEventMigrationRetirementRemainsDisabledUntilTodo7Horizon(t *testing.T) {
	gate := RetirementGate{}
	status := gate.Evaluate(context.Background(), DisabledRetirementHorizonSource{}, migrationTestTime)
	if status.Allowed || status.Dependency != "Todo 7 persisted maximum spool/retry horizon" {
		t.Fatalf("retirement gate unexpectedly opened: %+v", status)
	}
}

func TestEventMigrationRetirementCallerCannotForgeReadiness(t *testing.T) {
	gate := RetirementGate{Enabled: true}
	status := gate.Evaluate(context.Background(), callerControlledHorizonSource{}, migrationTestTime.Add(365*24*time.Hour))
	if status.Allowed {
		t.Fatalf("caller-controlled source forged retirement readiness: %+v", status)
	}
}

type callerControlledHorizonSource struct{}

func (callerControlledHorizonSource) Load(context.Context) (PersistedRetirementHorizon, error) {
	return PersistedRetirementHorizon{}, nil
}

func TestEventMigrationDualWriteTargetsAreDeterministic(t *testing.T) {
	state := NewMigrationState()
	if err := state.Advance(PhaseDualWrite); err != nil {
		t.Fatalf("advance dual write: %v", err)
	}
	first := DeterministicEventUID(SourceAgentRuntime, "agent-1", "native-1")
	second := DeterministicEventUID(SourceAgentRuntime, "agent-1", "native-1")
	if first != second || state.WriteMode() != WriteDual {
		t.Fatalf("dual-write identity not deterministic: %q %q %s", first, second, state.WriteMode())
	}
}

func TestEventMigrationObserveReportsLegacyReadsAndReconciliationMismatch(t *testing.T) {
	observation := ObserveMigration(MigrationObservationInput{LegacyReads: 2, CanonicalReads: 8, Quarantined: 1, ReconciliationMatch: false})
	if observation.LegacyReadRatio != 0.2 || len(observation.Warnings) != 2 {
		t.Fatalf("observe metrics did not expose migration risk: %+v", observation)
	}
}
