package contracts

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrInvalidMigrationTransition = errors.New("invalid migration transition")
	ErrStaleMigrationState        = errors.New("stale migration state")
)

type MigrationPhase string

const (
	PhaseReaderFirst  MigrationPhase = "reader_first"
	PhaseDualWrite    MigrationPhase = "dual_write"
	PhaseReconcile    MigrationPhase = "reconcile"
	PhaseReadSwitch   MigrationPhase = "read_switch"
	PhaseObserve      MigrationPhase = "observe"
	PhaseRetireLegacy MigrationPhase = "retire_legacy"
)

type ReadSource string

const (
	ReadLegacy    ReadSource = "legacy"
	ReadCanonical ReadSource = "canonical"
)

type WriteMode string

const (
	WriteLegacy WriteMode = "legacy_only"
	WriteDual   WriteMode = "dual_write"
)

type MigrationSnapshot struct {
	Phase    MigrationPhase `json:"phase"`
	Revision uint64         `json:"revision"`
}

type MigrationState struct {
	mu       sync.RWMutex
	phase    MigrationPhase
	revision uint64
}

func NewMigrationState() *MigrationState {
	return &MigrationState{phase: PhaseReaderFirst, revision: 1}
}

func NewMigrationStateFromSnapshot(snapshot MigrationSnapshot) (*MigrationState, error) {
	if !isActiveMigrationPhase(snapshot.Phase) || snapshot.Revision < minimumRevision(snapshot.Phase) {
		return nil, fmt.Errorf("restore phase=%s revision=%d: %w", snapshot.Phase, snapshot.Revision, ErrStaleMigrationState)
	}
	return &MigrationState{phase: snapshot.Phase, revision: snapshot.Revision}, nil
}

func (state *MigrationState) Advance(next MigrationPhase) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if expectedNext(state.phase) != next || next == PhaseRetireLegacy {
		return fmt.Errorf("%s to %s: %w", state.phase, next, ErrInvalidMigrationTransition)
	}
	state.phase = next
	state.revision++
	return nil
}

func (state *MigrationState) RetireLegacy() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.phase != PhaseObserve {
		return fmt.Errorf("%s to %s: %w", state.phase, PhaseRetireLegacy, ErrInvalidMigrationTransition)
	}
	state.phase = PhaseRetireLegacy
	state.revision++
	return nil
}

func (state *MigrationState) Rollback() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	switch state.phase {
	case PhaseReadSwitch, PhaseObserve:
		state.phase = PhaseReconcile
	case PhaseReconcile:
		state.phase = PhaseDualWrite
	case PhaseDualWrite:
		state.phase = PhaseReaderFirst
	case PhaseReaderFirst, PhaseRetireLegacy:
		return fmt.Errorf("from %s: %w", state.phase, ErrInvalidMigrationTransition)
	default:
		return fmt.Errorf("unknown phase %s: %w", state.phase, ErrStaleMigrationState)
	}
	state.revision++
	return nil
}

func (state *MigrationState) Restore(snapshot MigrationSnapshot) error {
	if !isActiveMigrationPhase(snapshot.Phase) || snapshot.Revision == 0 {
		return fmt.Errorf("restore phase=%s revision=%d: %w", snapshot.Phase, snapshot.Revision, ErrStaleMigrationState)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if snapshot.Revision < state.revision || snapshot.Revision > state.revision+1 {
		return fmt.Errorf("restore revision=%d current=%d: %w", snapshot.Revision, state.revision, ErrStaleMigrationState)
	}
	if snapshot.Revision == state.revision {
		if snapshot.Phase == state.phase {
			return nil
		}
		return fmt.Errorf("restore phase=%s current=%s at revision=%d: %w", snapshot.Phase, state.phase, state.revision, ErrStaleMigrationState)
	}
	if !isAdjacentMigrationPhase(state.phase, snapshot.Phase) {
		return fmt.Errorf("restore phase=%s current=%s: %w", snapshot.Phase, state.phase, ErrStaleMigrationState)
	}
	state.phase = snapshot.Phase
	state.revision = snapshot.Revision
	return nil
}

func isAdjacentMigrationPhase(current, next MigrationPhase) bool {
	if expectedNext(current) == next {
		return true
	}
	switch current {
	case PhaseDualWrite:
		return next == PhaseReaderFirst
	case PhaseReconcile:
		return next == PhaseDualWrite
	case PhaseReadSwitch, PhaseObserve:
		return next == PhaseReconcile
	case PhaseReaderFirst, PhaseRetireLegacy:
		return false
	default:
		return false
	}
}

func (state *MigrationState) Snapshot() MigrationSnapshot {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return MigrationSnapshot{Phase: state.phase, Revision: state.revision}
}

func (state *MigrationState) Phase() MigrationPhase { return state.Snapshot().Phase }

func (state *MigrationState) ReadSource() ReadSource {
	phase := state.Phase()
	if phase == PhaseReadSwitch || phase == PhaseObserve {
		return ReadCanonical
	}
	return ReadLegacy
}

func (state *MigrationState) WriteMode() WriteMode {
	if state.Phase() == PhaseReaderFirst {
		return WriteLegacy
	}
	return WriteDual
}

func expectedNext(phase MigrationPhase) MigrationPhase {
	switch phase {
	case PhaseReaderFirst:
		return PhaseDualWrite
	case PhaseDualWrite:
		return PhaseReconcile
	case PhaseReconcile:
		return PhaseReadSwitch
	case PhaseReadSwitch:
		return PhaseObserve
	case PhaseObserve, PhaseRetireLegacy:
		return ""
	default:
		return ""
	}
}

func isActiveMigrationPhase(phase MigrationPhase) bool {
	switch phase {
	case PhaseReaderFirst, PhaseDualWrite, PhaseReconcile, PhaseReadSwitch, PhaseObserve:
		return true
	default:
		return false
	}
}

func minimumRevision(phase MigrationPhase) uint64 {
	switch phase {
	case PhaseReaderFirst:
		return 1
	case PhaseDualWrite:
		return 2
	case PhaseReconcile:
		return 3
	case PhaseReadSwitch:
		return 4
	case PhaseObserve:
		return 5
	case PhaseRetireLegacy:
		return ^uint64(0)
	default:
		return ^uint64(0)
	}
}
