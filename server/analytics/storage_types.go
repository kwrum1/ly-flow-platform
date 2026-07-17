package analytics

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidStoragePhase = errors.New("invalid event storage phase")
	ErrInvalidTransition   = errors.New("invalid event storage transition")
	ErrStorageBackpressure = errors.New("event storage backpressure")
	ErrClickHouseDiskFull  = errors.New("clickhouse disk full")
	ErrConsistencyMismatch = errors.New("event storage consistency mismatch")
	ErrRetentionUnmeasured = errors.New("event retention capacity is unmeasured")
)

type StoragePhase string

const (
	PhaseLegacy       StoragePhase = "legacy"
	PhaseDualWrite    StoragePhase = "dual_write"
	PhaseReconcile    StoragePhase = "reconcile"
	PhaseReadSwitch   StoragePhase = "read_switch"
	PhaseObserve      StoragePhase = "observe"
	PhaseRetireLegacy StoragePhase = "retire_legacy"
)

type ReadAuthority string

const (
	ReadPostgres   ReadAuthority = "postgres"
	ReadReconciled ReadAuthority = "postgres_clickhouse_reconciled"
	ReadClickHouse ReadAuthority = "clickhouse"
)

type WriteAuthority string

const (
	WritePostgres              WriteAuthority = "postgres"
	WritePostgresAndClickHouse WriteAuthority = "postgres_clickhouse"
)

type ControlAuthority string

const ControlPostgres ControlAuthority = "postgres"

type StoragePolicy struct {
	Read    ReadAuthority
	Write   WriteAuthority
	Control ControlAuthority
}

func PolicyForPhase(phase StoragePhase) (StoragePolicy, error) {
	switch phase {
	case PhaseLegacy:
		return StoragePolicy{Read: ReadPostgres, Write: WritePostgres, Control: ControlPostgres}, nil
	case PhaseDualWrite:
		return StoragePolicy{Read: ReadPostgres, Write: WritePostgresAndClickHouse, Control: ControlPostgres}, nil
	case PhaseReconcile:
		return StoragePolicy{Read: ReadReconciled, Write: WritePostgresAndClickHouse, Control: ControlPostgres}, nil
	case PhaseReadSwitch, PhaseObserve, PhaseRetireLegacy:
		return StoragePolicy{Read: ReadClickHouse, Write: WritePostgresAndClickHouse, Control: ControlPostgres}, nil
	default:
		return StoragePolicy{}, fmt.Errorf("phase %q: %w", phase, ErrInvalidStoragePhase)
	}
}

type RetentionPolicy struct {
	ClaimsEnabled bool
	MeasuredAt    time.Time
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{}
}

func (policy RetentionPolicy) AuthorizeExpiry(_ time.Time) error {
	if !policy.ClaimsEnabled || policy.MeasuredAt.IsZero() {
		return ErrRetentionUnmeasured
	}
	return nil
}

type ReconciliationReport struct {
	PostgresCount      int
	ClickHouseCount    int
	PostgresChecksum   string
	ClickHouseChecksum string
	Match              bool
}

type SearchResult struct {
	Events    []EventRecord
	Authority ReadAuthority
	Checksum  string
}

type MigrationMetrics struct {
	WriteAttempts       uint64
	BackpressureEvents  uint64
	Reconciliations     uint64
	ConsistencyFailures uint64
}

type MigrationStatus struct {
	Phase                  StoragePhase
	Revision               uint64
	Owner                  string
	CheckpointUID          string
	BackupCheckpointUID    string
	RollbackUntil          time.Time
	LegacyRetired          bool
	RetentionClaimsEnabled bool
	Degraded               bool
	LastError              string
	PendingWrites          int64
	WriteRevision          uint64
	ReconcileWriteRevision uint64
	ReconcileCheckpointUID string
	LastReconcileMatch     bool
	Metrics                MigrationMetrics
}
