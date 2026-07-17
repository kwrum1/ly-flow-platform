package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/redis/go-redis/v9"
)

func (runtime *EventMigrationRuntime) Read(ctx context.Context, limit int64) ([]contracts.CanonicalSecurityEvent, contracts.ReadSource, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	runtime.mu.RLock()
	source := runtime.state.ReadSource()
	runtime.mu.RUnlock()
	var events []contracts.CanonicalSecurityEvent
	var err error
	if source == contracts.ReadCanonical {
		events, err = runtime.readCanonical(ctx, limit)
		if err == nil {
			runtime.canonicalReads.Add(uint64(len(events)))
		}
	} else {
		events, err = runtime.readLegacy(ctx, limit)
		if err == nil {
			runtime.legacyReads.Add(uint64(len(events)))
			if len(events) > 0 {
				err = runtime.horizonStore.Refresh(ctx, runtime.maximumHorizon, true, time.Now().UTC())
			}
		}
	}
	if err != nil {
		runtime.quarantined.Add(1)
		return nil, source, err
	}
	return events, source, nil
}

func (runtime *EventMigrationRuntime) readCanonical(ctx context.Context, limit int64) ([]contracts.CanonicalSecurityEvent, error) {
	messages, err := runtime.client.XRevRangeN(ctx, canonicalEventStream, "+", "-", limit).Result()
	if err != nil {
		return nil, fmt.Errorf("read canonical event stream: %w", err)
	}
	events := make([]contracts.CanonicalSecurityEvent, 0, len(messages))
	for _, message := range messages {
		data, ok := message.Values["data"].(string)
		if !ok {
			return nil, fmt.Errorf("canonical message %s has no string data", message.ID)
		}
		var identity struct {
			Identity contracts.SourceIdentity `json:"identity"`
		}
		if err := json.Unmarshal([]byte(data), &identity); err != nil {
			return nil, fmt.Errorf("decode canonical identity %s: %w", message.ID, err)
		}
		event, _, err := contracts.ParseCanonical([]byte(data), contracts.PrincipalIdentity(identity.Identity.PrincipalID))
		if err != nil {
			return nil, fmt.Errorf("parse canonical message %s: %w", message.ID, err)
		}
		events = append(events, event)
	}
	return events, nil
}

func (runtime *EventMigrationRuntime) readLegacy(ctx context.Context, limit int64) ([]contracts.CanonicalSecurityEvent, error) {
	messages, err := runtime.client.XRevRangeN(ctx, legacyComponentAlertStream, "+", "-", limit).Result()
	if err != nil {
		return nil, fmt.Errorf("read legacy component alert stream: %w", err)
	}
	events := make([]contracts.CanonicalSecurityEvent, 0, len(messages))
	for _, message := range messages {
		data, ok := message.Values["data"].(string)
		if !ok {
			return nil, fmt.Errorf("legacy message %s has no string data", message.ID)
		}
		var alert contracts.ComponentAlert
		if err := json.Unmarshal([]byte(data), &alert); err != nil {
			return nil, fmt.Errorf("decode legacy component alert %s: %w", message.ID, err)
		}
		if err := alert.Validate(); err != nil {
			return nil, fmt.Errorf("validate legacy component alert %s: %w", message.ID, err)
		}
		event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), alert.OccurredAt)
		if err != nil {
			return nil, fmt.Errorf("adapt legacy component alert %s: %w", message.ID, err)
		}
		events = append(events, event)
	}
	return events, nil
}

func (runtime *EventMigrationRuntime) Reconcile(ctx context.Context) (contracts.ReconciliationReport, error) {
	legacy, err := runtime.readLegacy(ctx, 1000)
	if err != nil {
		return contracts.ReconciliationReport{}, err
	}
	canonical, err := runtime.readCanonical(ctx, 1000)
	if err != nil {
		return contracts.ReconciliationReport{}, err
	}
	legacyRecords, err := reconcileRecords(legacy)
	if err != nil {
		return contracts.ReconciliationReport{}, err
	}
	canonicalRecords, err := reconcileRecords(canonical)
	if err != nil {
		return contracts.ReconciliationReport{}, err
	}
	report := contracts.Reconcile(legacyRecords, canonicalRecords)
	runtime.reconciliation.Store(report.Match)
	return report, nil
}

func reconcileRecords(events []contracts.CanonicalSecurityEvent) ([]contracts.ReconcileRecord, error) {
	records := make([]contracts.ReconcileRecord, 0, len(events))
	for _, event := range events {
		stable := struct {
			EventUID   string                   `json:"event_uid"`
			EventType  string                   `json:"event_type"`
			Severity   contracts.AlertSeverity  `json:"severity"`
			Identity   contracts.SourceIdentity `json:"identity"`
			EventAt    time.Time                `json:"event_at"`
			ObservedAt time.Time                `json:"observed_at"`
			Source     contracts.EventSource    `json:"source"`
			NativeID   string                   `json:"native_event_id"`
			Attack     contracts.AttackMapping  `json:"attack"`
			Payload    json.RawMessage          `json:"payload"`
		}{EventUID: event.EventUID, EventType: event.EventType, Severity: event.Severity, Identity: event.Identity,
			EventAt: event.Timestamps.EventAt, ObservedAt: event.Timestamps.ObservedAt, Source: event.Provenance.Source,
			NativeID: event.Provenance.NativeEventID, Attack: event.Attack, Payload: event.Payload}
		payload, err := json.Marshal(stable)
		if err != nil {
			return nil, fmt.Errorf("encode reconciliation record %s: %w", event.EventUID, err)
		}
		records = append(records, contracts.ReconcileRecord{EventUID: event.EventUID, Payload: payload})
	}
	return records, nil
}

func (runtime *EventMigrationRuntime) Observe() contracts.MigrationObservation {
	return contracts.ObserveMigration(contracts.MigrationObservationInput{
		LegacyReads: runtime.legacyReads.Load(), CanonicalReads: runtime.canonicalReads.Load(),
		Quarantined: runtime.quarantined.Load(), ReconciliationMatch: runtime.reconciliation.Load(),
	})
}

func (runtime *EventMigrationRuntime) Delete(ctx context.Context, eventUID string) error {
	legacyIDs, err := runtime.streamMessageIDs(ctx, legacyComponentAlertStream, eventUID)
	if err != nil {
		return err
	}
	canonicalIDs, err := runtime.streamMessageIDs(ctx, canonicalEventStream, eventUID)
	if err != nil {
		return err
	}
	pipeline := runtime.client.TxPipeline()
	if len(legacyIDs) > 0 {
		pipeline.XDel(ctx, legacyComponentAlertStream, legacyIDs...)
	}
	if len(canonicalIDs) > 0 {
		pipeline.XDel(ctx, canonicalEventStream, canonicalIDs...)
	}
	pipeline.HDel(ctx, migrationLegacyIndexKey, eventUID)
	pipeline.HDel(ctx, migrationCanonicalIndexKey, eventUID)
	if _, err := pipeline.Exec(ctx); err != nil {
		return fmt.Errorf("delete governed event %s: %w", eventUID, err)
	}
	return nil
}

func (runtime *EventMigrationRuntime) streamMessageIDs(ctx context.Context, stream, eventUID string) ([]string, error) {
	messages, err := runtime.client.XRange(ctx, stream, "-", "+").Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("scan stream %s: %w", stream, err)
	}
	ids := make([]string, 0, 1)
	for _, message := range messages {
		if stream == canonicalEventStream && fmt.Sprint(message.Values["event_uid"]) == eventUID {
			ids = append(ids, message.ID)
			continue
		}
		if stream == legacyComponentAlertStream {
			var alert contracts.ComponentAlert
			if json.Unmarshal([]byte(fmt.Sprint(message.Values["data"])), &alert) == nil &&
				contracts.DeterministicEventUID(sourceForAlert(alert), alert.Entities.AgentID, alert.ID) == eventUID {
				ids = append(ids, message.ID)
			}
		}
	}
	return ids, nil
}

func sourceForAlert(alert contracts.ComponentAlert) contracts.EventSource {
	event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), time.Unix(1, 0).UTC())
	if err != nil {
		return contracts.SourceSecurityEngine
	}
	return event.Provenance.Source
}
