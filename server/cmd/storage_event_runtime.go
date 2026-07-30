package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/analytics"
)

type StorageEventRuntime struct {
	migration *analytics.StorageMigration
}

func newProductionStorageEventRuntime(ctx context.Context, postgres *pgxpool.Pool) (*StorageEventRuntime, error) {
	rollbackHours, err := strconv.Atoi(getEnv("EVENT_STORAGE_ROLLBACK_HOURS", "24"))
	if err != nil || rollbackHours <= 0 {
		return nil, fmt.Errorf("EVENT_STORAGE_ROLLBACK_HOURS must be a positive integer")
	}
	clickhouse, err := analytics.NewHTTPClickHouse(analytics.HTTPClickHouseConfig{
		Endpoint: getEnv("CLICKHOUSE_ADDR", "http://clickhouse:8123"),
		Database: getEnv("CLICKHOUSE_DB", "lyflow"),
		Username: getEnv("CLICKHOUSE_USER", "lyflow"),
		Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		Timeout:  time.Duration(toInt(getEnv("CLICKHOUSE_TIMEOUT_SECONDS", "10"))) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	migration, err := analytics.NewStorageMigration(analytics.StorageMigrationConfig{
		Postgres: postgres, ClickHouse: clickhouse, Owner: getEnv("EVENT_STORAGE_MIGRATION_OWNER", "ly-server"),
		RollbackWindow: time.Duration(rollbackHours) * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	if err := migration.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate event storage: %w", err)
	}
	return &StorageEventRuntime{migration: migration}, nil
}

func (runtime *StorageEventRuntime) WriteCanonical(ctx context.Context, event contracts.CanonicalSecurityEvent) error {
	payload, err := contracts.MarshalCanonical(event)
	if err != nil {
		return err
	}
	version := event.Timestamps.IngestedAt.UnixNano()
	if version <= 0 {
		return fmt.Errorf("canonical event %s has invalid ingestion version", event.EventUID)
	}
	record := analytics.EventRecord{
		ID: event.EventUID, Version: uint64(version), Timestamp: event.Timestamps.EventAt,
		SourceModule: string(event.Provenance.Source), EventType: event.EventType, Severity: string(event.Severity),
		AgentID: event.Identity.AgentID, ChainID: event.CorrelationID, EntityID: event.Identity.PrincipalID,
		RawReference: event.Provenance.NativeEventID, Message: event.EventType, PayloadJSON: string(payload),
	}
	return runtime.migration.Write(ctx, record)
}

func (runtime *StorageEventRuntime) WriteComponentAlert(ctx context.Context, alert contracts.ComponentAlert, ingestedAt time.Time) (MigrationWriteReceipt, error) {
	event, _, err := canonicalComponentAlertPayload(alert, ingestedAt)
	if err != nil {
		return MigrationWriteReceipt{}, err
	}
	if err := runtime.WriteCanonical(ctx, event); err != nil {
		return MigrationWriteReceipt{}, err
	}
	return MigrationWriteReceipt{EventUID: event.EventUID, CanonicalMessageID: event.EventUID}, nil
}

func (runtime *StorageEventRuntime) Read(ctx context.Context, limit int64) ([]contracts.CanonicalSecurityEvent, analytics.ReadAuthority, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	result, err := runtime.migration.Search(ctx, int(limit))
	if err != nil {
		return nil, "", err
	}
	events := make([]contracts.CanonicalSecurityEvent, 0, len(result.Events))
	for _, record := range result.Events {
		normalizedEvent, err := normalizeStoredCanonicalPayload(record.ID, record.PayloadJSON)
		if err != nil {
			return nil, "", err
		}
		var stored contracts.CanonicalSecurityEvent
		if err := json.Unmarshal(normalizedEvent, &stored); err != nil {
			return nil, "", fmt.Errorf("decode normalized event identity %s: %w", record.ID, err)
		}
		event, _, err := contracts.ParseCanonical(normalizedEvent, contracts.PrincipalIdentity(stored.Identity.PrincipalID))
		if err != nil {
			return nil, "", fmt.Errorf("parse stored canonical event %s: %w", record.ID, err)
		}
		events = append(events, event)
	}
	return events, result.Authority, nil
}

func (runtime *StorageEventRuntime) ReadCanonicalPayloads(ctx context.Context, limit int64) ([][]byte, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	result, err := runtime.migration.Search(ctx, int(limit))
	if err != nil {
		return nil, err
	}
	payloads := make([][]byte, 0, len(result.Events))
	for _, record := range result.Events {
		normalized, err := normalizeStoredCanonicalPayload(record.ID, record.PayloadJSON)
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, normalized)
	}
	return payloads, nil
}

func normalizeStoredCanonicalPayload(recordID, payloadJSON string) ([]byte, error) {
	var stored contracts.CanonicalSecurityEvent
	if err := json.Unmarshal([]byte(payloadJSON), &stored); err != nil {
		return nil, fmt.Errorf("decode stored event identity %s: %w", recordID, err)
	}
	normalizedPayload, redactedFields, err := contracts.RedactJSON(stored.Payload)
	if err != nil {
		return nil, fmt.Errorf("normalize stored event payload %s: %w", recordID, err)
	}
	stored.Payload = normalizedPayload
	stored.Governance.RedactedFields = redactedFields
	normalizedEvent, err := json.Marshal(stored)
	if err != nil {
		return nil, fmt.Errorf("normalize stored canonical event %s: %w", recordID, err)
	}
	if _, _, err := contracts.ParseCanonical(normalizedEvent, contracts.PrincipalIdentity(stored.Identity.PrincipalID)); err != nil {
		return nil, fmt.Errorf("validate normalized canonical event %s: %w", recordID, err)
	}
	return normalizedEvent, nil
}

func (runtime *StorageEventRuntime) Delete(ctx context.Context, eventUID string) error {
	return runtime.migration.Delete(ctx, eventUID)
}
