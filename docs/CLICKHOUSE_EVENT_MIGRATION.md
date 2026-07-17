# ClickHouse event-storage migration

## Authority by phase

PostgreSQL owns migration control metadata in every phase. The owner, phase revision, backfill checkpoint, backup checkpoint, rollback deadline, pending-write count, degraded state, and migration metrics are persisted in `lyflow_event_storage_control` and `lyflow_event_storage_outbox`.

| Phase | Event writes | Event search |
|---|---|---|
| `legacy` | PostgreSQL only | PostgreSQL |
| `dual_write` | PostgreSQL plus durable ClickHouse outbox | PostgreSQL |
| `reconcile` | PostgreSQL plus durable ClickHouse outbox | Reconciled PostgreSQL and ClickHouse; mismatches fail closed |
| `read_switch` | PostgreSQL plus durable ClickHouse outbox | ClickHouse only |
| `observe` | PostgreSQL plus durable ClickHouse outbox | ClickHouse only |
| `retire_legacy` | PostgreSQL plus durable ClickHouse outbox | ClickHouse only; PostgreSQL data remains during rollback window |

The read switch is rejected until a count and SHA-256 checksum reconciliation succeeds. Advancing to `read_switch` saves the backfill checkpoint and opens the configured rollback window. Rollback is nondestructive, restores reconciled dual-read, and remains available after legacy retirement until that deadline.

## Consistency contract

PostgreSQL is committed before ClickHouse delivery. Dual-write phases place the UID in the PostgreSQL outbox in the same transaction as the legacy event. ClickHouse failure therefore returns explicit `ErrStorageBackpressure`, leaves a retryable pending row, and marks control health degraded; it never reports a silently converged write.

ClickHouse storage uses `ReplacingMergeTree(version)` ordered by `event_uid`. Delivery is idempotent and may temporarily retain physical duplicate versions. Every canonical search and reconciliation uses `FINAL`, so the query-time contract is one highest-version row per UID. Reconciliation compares normalized UTC timestamps, counts, and deterministic checksums across stores.

## Migrations and retention

PostgreSQL and ClickHouse each have an append-only schema-version ledger. Reapplying migrations is safe and does not drop event data. Phase rollback changes control authority only; it does not reverse or delete schema/data migrations.

Retention claims are disabled. `ExpireLegacy` returns `ErrRetentionUnmeasured` and deletes nothing until measured capacity evidence and a separate retention-enablement change exist. No ClickHouse TTL is installed.

## Failure handling

- Connection refusal, request timeout, HTTP failure, malformed success responses, and disk-full responses are surfaced to callers.
- Disk-full responses are classified as both `ErrClickHouseDiskFull` and `ErrStorageBackpressure`.
- Pending-write and backpressure metrics stay in PostgreSQL and remain observable while ClickHouse is unavailable.
- The offline QA harness uses only cached exact Postgres 16 and ClickHouse 24.8 images, isolated tmpfs data, bounded commands, and trap cleanup.
