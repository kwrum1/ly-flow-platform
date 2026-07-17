package analytics

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const clickHouseEventTableDDL = `CREATE TABLE IF NOT EXISTS lyflow_security_events (
  event_uid String,
  version UInt64,
  timestamp DateTime64(3, 'UTC'),
  source_module LowCardinality(String),
  event_type String,
  severity LowCardinality(String),
  agent_id String,
  host_id String,
  chain_id String,
  entity_id String,
  raw_reference String,
  message String,
  payload_json String
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_uid)`

const ClickHouseFinalQuery = `SELECT event_uid, version, timestamp, source_module, event_type, severity, agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json FROM lyflow_security_events FINAL ORDER BY timestamp DESC`

const ClickHouseEventMigrationDDL = clickHouseEventTableDDL + ";\n" + ClickHouseFinalQuery

var postgresStorageMigrations = []struct {
	version uint64
	query   string
}{
	{1, `CREATE TABLE IF NOT EXISTS lyflow_event_storage_events (
event_uid TEXT PRIMARY KEY, version BIGINT NOT NULL, event_timestamp TIMESTAMPTZ NOT NULL,
source_module TEXT NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL,
agent_id TEXT NOT NULL, host_id TEXT NOT NULL, chain_id TEXT NOT NULL, entity_id TEXT NOT NULL,
raw_reference TEXT NOT NULL, message TEXT NOT NULL, payload_json JSONB NOT NULL)`},
	{2, `CREATE TABLE IF NOT EXISTS lyflow_event_storage_control (
singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), phase TEXT NOT NULL, revision BIGINT NOT NULL,
owner TEXT NOT NULL, checkpoint_uid TEXT NOT NULL DEFAULT '', backup_checkpoint_uid TEXT NOT NULL DEFAULT '',
rollback_until TIMESTAMPTZ, legacy_retired BOOLEAN NOT NULL DEFAULT FALSE,
retention_claims_enabled BOOLEAN NOT NULL DEFAULT FALSE, degraded BOOLEAN NOT NULL DEFAULT FALSE,
last_error TEXT NOT NULL DEFAULT '', last_reconcile_match BOOLEAN NOT NULL DEFAULT FALSE,
write_attempts BIGINT NOT NULL DEFAULT 0, backpressure_events BIGINT NOT NULL DEFAULT 0,
reconciliations BIGINT NOT NULL DEFAULT 0, consistency_failures BIGINT NOT NULL DEFAULT 0)`},
	{3, `CREATE TABLE IF NOT EXISTS lyflow_event_storage_outbox (
event_uid TEXT PRIMARY KEY REFERENCES lyflow_event_storage_events(event_uid) ON DELETE CASCADE,
queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`},
	{4, `ALTER TABLE lyflow_event_storage_outbox ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1`},
	{5, `ALTER TABLE lyflow_event_storage_control
ADD COLUMN IF NOT EXISTS write_revision BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS reconcile_write_revision BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS reconcile_checkpoint_uid TEXT NOT NULL DEFAULT ''`},
}

var clickHouseStorageMigrations = []struct {
	version uint64
	query   string
}{
	{1, `CREATE TABLE IF NOT EXISTS lyflow_event_storage_migrations (
version UInt64, applied_at DateTime64(3, 'UTC')) ENGINE = ReplacingMergeTree(applied_at) ORDER BY version`},
	{2, clickHouseEventTableDDL},
	{3, ""},
}

func (migration *StorageMigration) Migrate(ctx context.Context) error {
	if _, err := migration.postgres.Exec(ctx, `CREATE TABLE IF NOT EXISTS lyflow_event_storage_migrations (
version BIGINT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		return fmt.Errorf("create Postgres migration ledger: %w", err)
	}
	for _, item := range postgresStorageMigrations {
		transaction, err := migration.postgres.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin Postgres migration %d: %w", item.version, err)
		}
		var applied bool
		if err := transaction.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM lyflow_event_storage_migrations WHERE version=$1)`, item.version).Scan(&applied); err != nil {
			_ = transaction.Rollback(ctx)
			return fmt.Errorf("check Postgres migration %d: %w", item.version, err)
		}
		if applied {
			_ = transaction.Rollback(ctx)
			continue
		}
		if _, err := transaction.Exec(ctx, item.query); err != nil {
			_ = transaction.Rollback(ctx)
			return fmt.Errorf("apply Postgres migration %d: %w", item.version, err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO lyflow_event_storage_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING`, item.version); err != nil {
			_ = transaction.Rollback(ctx)
			return fmt.Errorf("record Postgres migration %d: %w", item.version, err)
		}
		if err := transaction.Commit(ctx); err != nil {
			return fmt.Errorf("commit Postgres migration %d: %w", item.version, err)
		}
	}
	if _, err := migration.clickhouse.execute(ctx, clickHouseStorageMigrations[0].query); err != nil {
		return fmt.Errorf("create ClickHouse migration ledger: %w", err)
	}
	applied, err := migration.clickHouseAppliedMigrations(ctx)
	if err != nil {
		return err
	}
	for _, item := range clickHouseStorageMigrations {
		if applied[item.version] {
			continue
		}
		if item.version == 3 {
			err = migration.ensureVersionedClickHouseTable(ctx)
		} else {
			_, err = migration.clickhouse.execute(ctx, item.query)
		}
		if err != nil {
			return fmt.Errorf("apply ClickHouse migration %d: %w", item.version, err)
		}
		query := fmt.Sprintf("INSERT INTO lyflow_event_storage_migrations VALUES (%d, now64(3))", item.version)
		if _, err := migration.clickhouse.execute(ctx, query); err != nil {
			return fmt.Errorf("record ClickHouse migration %d: %w", item.version, err)
		}
	}
	_, err = migration.postgres.Exec(ctx, `INSERT INTO lyflow_event_storage_control(singleton, phase, revision, owner)
VALUES (TRUE, $1, 1, $2) ON CONFLICT (singleton) DO NOTHING`, PhaseLegacy, migration.owner)
	if err != nil {
		return fmt.Errorf("initialize Postgres migration control: %w", err)
	}
	return nil
}

func (migration *StorageMigration) clickHouseAppliedMigrations(ctx context.Context) (map[uint64]bool, error) {
	body, err := migration.clickhouse.execute(ctx, `SELECT version FROM lyflow_event_storage_migrations FINAL ORDER BY version FORMAT TabSeparated`)
	if err != nil {
		return nil, fmt.Errorf("read ClickHouse migration ledger: %w", err)
	}
	applied := make(map[uint64]bool)
	for _, line := range strings.Fields(string(body)) {
		version, err := strconv.ParseUint(line, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse ClickHouse migration version %q: %w", line, err)
		}
		applied[version] = true
	}
	return applied, nil
}

func (migration *StorageMigration) ensureVersionedClickHouseTable(ctx context.Context) error {
	engineBody, err := migration.clickhouse.execute(ctx, `SELECT engine FROM system.tables
WHERE database=currentDatabase() AND name='lyflow_security_events' FORMAT TabSeparated`)
	if err != nil {
		return err
	}
	engine := strings.TrimSpace(string(engineBody))
	if engine == "" {
		_, err = migration.clickhouse.execute(ctx, clickHouseEventTableDDL)
		return err
	}
	versionBody, err := migration.clickhouse.execute(ctx, `SELECT count() FROM system.columns
WHERE database=currentDatabase() AND table='lyflow_security_events' AND name='version' FORMAT TabSeparated`)
	if err != nil {
		return err
	}
	hasVersion := strings.TrimSpace(string(versionBody)) == "1"
	if engine == "ReplacingMergeTree" && hasVersion {
		return nil
	}
	transitionTable := "lyflow_security_events_versioned_transition"
	if _, err := migration.clickhouse.execute(ctx, "DROP TABLE IF EXISTS "+transitionTable); err != nil {
		return err
	}
	transitionDDL := strings.Replace(clickHouseEventTableDDL, "lyflow_security_events", transitionTable, 1)
	if _, err := migration.clickhouse.execute(ctx, transitionDDL); err != nil {
		return err
	}
	versionExpression := "toUInt64(1)"
	if hasVersion {
		versionExpression = "version"
	}
	copyQuery := `INSERT INTO ` + transitionTable + ` SELECT event_uid, ` + versionExpression + `, timestamp,
source_module, event_type, severity, agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json
FROM lyflow_security_events`
	if _, err := migration.clickhouse.execute(ctx, copyQuery); err != nil {
		return err
	}
	_, err = migration.clickhouse.execute(ctx, `RENAME TABLE lyflow_security_events TO lyflow_security_events_pre_versioned,
lyflow_security_events_versioned_transition TO lyflow_security_events`)
	return err
}
