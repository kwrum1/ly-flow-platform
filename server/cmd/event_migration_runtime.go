package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"
)

const (
	legacyComponentAlertStream = "component_alerts:v2"
	canonicalEventStream       = "security_events:v1"
	migrationStateKey          = "event_migration:state"
	migrationLegacyIndexKey    = "event_migration:legacy_ids"
	migrationCanonicalIndexKey = "event_migration:canonical_ids"
)

type MigrationWriteReceipt struct {
	EventUID           string `json:"event_uid"`
	LegacyMessageID    string `json:"legacy_message_id"`
	CanonicalMessageID string `json:"canonical_message_id,omitempty"`
}

type EventMigrationRuntime struct {
	client         *redis.Client
	mu             sync.RWMutex
	state          *contracts.MigrationState
	legacyReads    atomic.Uint64
	canonicalReads atomic.Uint64
	quarantined    atomic.Uint64
	reconciliation atomic.Bool
	horizonStore   transport.RedisHorizonStore
	maximumHorizon time.Duration
}

func NewEventMigrationRuntime(ctx context.Context, client *redis.Client, configured contracts.MigrationPhase) (*EventMigrationRuntime, error) {
	if client == nil {
		return nil, fmt.Errorf("migration runtime: redis unavailable")
	}
	state, err := loadMigrationState(ctx, client, configured)
	if err != nil {
		return nil, err
	}
	runtime := &EventMigrationRuntime{
		client: client, state: state, horizonStore: transport.NewRedisHorizonStore(client),
		maximumHorizon: 7 * 24 * time.Hour,
	}
	runtime.reconciliation.Store(true)
	if err := runtime.horizonStore.Refresh(ctx, runtime.maximumHorizon, false, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("initialize retirement horizon: %w", err)
	}
	return runtime, nil
}

func (runtime *EventMigrationRuntime) Snapshot() contracts.MigrationSnapshot {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.state.Snapshot()
}

func (runtime *EventMigrationRuntime) Advance(ctx context.Context, next contracts.MigrationPhase) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	previous := runtime.state.Snapshot()
	if err := runtime.state.Advance(next); err != nil {
		return err
	}
	if err := persistMigrationState(ctx, runtime.client, runtime.state.Snapshot()); err != nil {
		restored, restoreErr := contracts.NewMigrationStateFromSnapshot(previous)
		if restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		runtime.state = restored
		return err
	}
	return nil
}

func (runtime *EventMigrationRuntime) Rollback(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	previous := runtime.state.Snapshot()
	if err := runtime.state.Rollback(); err != nil {
		return err
	}
	if err := persistMigrationState(ctx, runtime.client, runtime.state.Snapshot()); err != nil {
		restored, restoreErr := contracts.NewMigrationStateFromSnapshot(previous)
		if restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		runtime.state = restored
		return err
	}
	return nil
}

func (runtime *EventMigrationRuntime) Retire(ctx context.Context, now time.Time) error {
	if err := runtime.horizonStore.Refresh(ctx, runtime.maximumHorizon, false, now); err != nil {
		return fmt.Errorf("refresh retirement horizon: %w", err)
	}
	status := (contracts.RetirementGate{Enabled: true}).Evaluate(ctx, runtime.horizonStore, now)
	if !status.Allowed {
		return fmt.Errorf("retire legacy blocked: %s", status.Reason)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	previous := runtime.state.Snapshot()
	if err := runtime.state.RetireLegacy(); err != nil {
		return err
	}
	if err := persistMigrationState(ctx, runtime.client, runtime.state.Snapshot()); err != nil {
		restored, restoreErr := contracts.NewMigrationStateFromSnapshot(previous)
		if restoreErr != nil {
			return errors.Join(err, restoreErr)
		}
		runtime.state = restored
		return err
	}
	return nil
}

func (runtime *EventMigrationRuntime) RetirementStatus(ctx context.Context, now time.Time) contracts.RetirementStatus {
	if err := runtime.horizonStore.Refresh(ctx, runtime.maximumHorizon, false, now); err != nil {
		return contracts.RetirementStatus{Dependency: "Todo 7 persisted maximum spool/retry horizon", Reason: err.Error()}
	}
	return (contracts.RetirementGate{Enabled: true}).Evaluate(ctx, runtime.horizonStore, now)
}

func (runtime *EventMigrationRuntime) WriteComponentAlert(ctx context.Context, alert contracts.ComponentAlert, ingestedAt time.Time) (MigrationWriteReceipt, error) {
	event, canonicalPayload, err := canonicalComponentAlertPayload(alert, ingestedAt)
	if err != nil {
		return MigrationWriteReceipt{}, err
	}
	legacyPayload, err := json.Marshal(alert)
	if err != nil {
		return MigrationWriteReceipt{}, fmt.Errorf("encode legacy component alert: %w", err)
	}
	runtime.mu.RLock()
	mode := runtime.state.WriteMode()
	runtime.mu.RUnlock()
	result, err := runtime.client.Eval(ctx, migrationWriteScript, []string{
		legacyComponentAlertStream, canonicalEventStream, migrationLegacyIndexKey, migrationCanonicalIndexKey,
	}, event.EventUID, string(mode), string(legacyPayload), string(canonicalPayload), alert.ID,
		string(alert.Category), string(alert.SourceEngine), alert.RuleID, string(alert.Severity),
		alert.OccurredAt.Format(time.RFC3339Nano), event.SchemaVersion, string(event.Provenance.Source),
		event.Timestamps.ObservedAt.Format(time.RFC3339Nano)).StringSlice()
	if err != nil {
		return MigrationWriteReceipt{}, fmt.Errorf("phase-aware component alert write: %w", err)
	}
	if len(result) != 2 {
		return MigrationWriteReceipt{}, fmt.Errorf("phase-aware component alert write returned %d values", len(result))
	}
	return MigrationWriteReceipt{EventUID: event.EventUID, LegacyMessageID: result[0], CanonicalMessageID: result[1]}, nil
}

func loadMigrationState(ctx context.Context, client *redis.Client, configured contracts.MigrationPhase) (*contracts.MigrationState, error) {
	data, err := client.Get(ctx, migrationStateKey).Bytes()
	if err == nil {
		var snapshot contracts.MigrationSnapshot
		if err := json.Unmarshal(data, &snapshot); err != nil {
			return nil, fmt.Errorf("decode persisted migration state: %w", err)
		}
		state, err := contracts.NewMigrationStateFromSnapshot(snapshot)
		if err != nil {
			return nil, fmt.Errorf("validate persisted migration state: %w", err)
		}
		return state, nil
	}
	if err != redis.Nil {
		return nil, fmt.Errorf("load persisted migration state: %w", err)
	}
	state := contracts.NewMigrationState()
	for state.Phase() != configured {
		next := nextConfiguredPhase(state.Phase())
		if next == "" {
			return nil, fmt.Errorf("configured migration phase %s is invalid", configured)
		}
		if err := state.Advance(next); err != nil {
			return nil, fmt.Errorf("advance configured migration phase %s: %w", configured, err)
		}
	}
	if err := persistMigrationState(ctx, client, state.Snapshot()); err != nil {
		return nil, err
	}
	return state, nil
}

func persistMigrationState(ctx context.Context, client *redis.Client, snapshot contracts.MigrationSnapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode migration state: %w", err)
	}
	if err := client.Set(ctx, migrationStateKey, data, 0).Err(); err != nil {
		return fmt.Errorf("persist migration state: %w", err)
	}
	return nil
}

func nextConfiguredPhase(phase contracts.MigrationPhase) contracts.MigrationPhase {
	switch phase {
	case contracts.PhaseReaderFirst:
		return contracts.PhaseDualWrite
	case contracts.PhaseDualWrite:
		return contracts.PhaseReconcile
	case contracts.PhaseReconcile:
		return contracts.PhaseReadSwitch
	case contracts.PhaseReadSwitch:
		return contracts.PhaseObserve
	case contracts.PhaseObserve, contracts.PhaseRetireLegacy:
		return ""
	default:
		return ""
	}
}

const migrationWriteScript = `
local legacy = redis.call('HGET', KEYS[3], ARGV[1])
if not legacy then
  legacy = redis.call('XADD', KEYS[1], '*', 'data', ARGV[3], 'event_uid', ARGV[1], 'id', ARGV[5], 'category', ARGV[6], 'source_engine', ARGV[7], 'rule_id', ARGV[8], 'severity', ARGV[9], 'occurred_at', ARGV[10])
  redis.call('HSET', KEYS[3], ARGV[1], legacy)
end
local canonical = redis.call('HGET', KEYS[4], ARGV[1]) or ''
if ARGV[2] == 'dual_write' and canonical == '' then
  canonical = redis.call('XADD', KEYS[2], '*', 'data', ARGV[4], 'event_uid', ARGV[1], 'schema_version', ARGV[11], 'source', ARGV[12], 'observed_at', ARGV[13])
  redis.call('HSET', KEYS[4], ARGV[1], canonical)
end
return {legacy, canonical}
`
