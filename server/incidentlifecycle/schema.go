package incidentlifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool             *pgxpool.Pool
	now              func() time.Time
	cutoverInterrupt func(cutoverStage) error
}

func NewPostgresStore(pool *pgxpool.Pool, now func() time.Time) *PostgresStore {
	if now == nil {
		now = time.Now
	}
	return &PostgresStore{pool: pool, now: now}
}

func (store *PostgresStore) EnsureSchema(ctx context.Context) error {
	if store == nil || store.pool == nil {
		return fmt.Errorf("incident lifecycle store unavailable")
	}
	if _, err := store.pool.Exec(ctx, incidentLifecycleSchema); err != nil {
		return fmt.Errorf("apply incident lifecycle migration 19: %w", err)
	}
	return nil
}

const incidentLifecycleSchema = `
CREATE TABLE IF NOT EXISTS incident_lifecycle_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO incident_lifecycle_schema_migrations (version,name)
VALUES (19,'persist_incident_lifecycle') ON CONFLICT (version) DO NOTHING;

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_chain_id TEXT NOT NULL,
    algorithm_version TEXT NOT NULL CHECK (algorithm_version = 'v2-active'),
    dedup_key TEXT NOT NULL,
    correlation_key TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open','triaged','processing','resolved','closed')),
    assignee TEXT NOT NULL DEFAULT '',
    suppressed_until TIMESTAMPTZ,
    suppression_reason TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    acknowledge_due_at TIMESTAMPTZ NOT NULL,
    resolve_due_at TIMESTAMPTZ NOT NULL,
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id,dedup_key)
);
CREATE INDEX IF NOT EXISTS incidents_status_updated_idx ON incidents (status,updated_at DESC);
CREATE INDEX IF NOT EXISTS incidents_source_chain_idx ON incidents (tenant_id,source_chain_id);

CREATE TABLE IF NOT EXISTS incident_evidence_lineage (
    id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    source_chain_id TEXT NOT NULL,
    algorithm_version TEXT NOT NULL CHECK (algorithm_version = 'v2-active'),
    event_uid TEXT NOT NULL,
    source_node_uid TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}',
    evidence_checksum TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    UNIQUE (incident_id,event_uid,source_node_uid,evidence_checksum)
);
CREATE INDEX IF NOT EXISTS incident_evidence_lineage_incident_idx ON incident_evidence_lineage (incident_id,observed_at);

CREATE TABLE IF NOT EXISTS incident_suppressions (
    id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    dedup_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    actor_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_suppressions_active_idx ON incident_suppressions (dedup_key,expires_at DESC);

CREATE TABLE IF NOT EXISTS incident_lifecycle_audit (
    id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('applied','rejected')),
    reason TEXT NOT NULL DEFAULT '',
    incident_version BIGINT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE incident_lifecycle_audit ADD COLUMN IF NOT EXISTS payload_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS incident_lifecycle_audit_incident_idx ON incident_lifecycle_audit (incident_id,id);

CREATE TABLE IF NOT EXISTS incident_lifecycle_legacy_snapshots (
    name TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    checksum TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    captured INTEGER NOT NULL,
    importable_fields JSONB NOT NULL,
    unrecoverable_history INTEGER NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_lifecycle_cutover_audit (
    name TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    captured INTEGER NOT NULL,
    imported INTEGER NOT NULL,
    unrecoverable INTEGER NOT NULL,
    report JSONB NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION reject_incident_history_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'incident lifecycle history is immutable';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS incident_evidence_lineage_immutable ON incident_evidence_lineage;
CREATE TRIGGER incident_evidence_lineage_immutable BEFORE UPDATE OR DELETE ON incident_evidence_lineage
FOR EACH ROW EXECUTE FUNCTION reject_incident_history_mutation();
DROP TRIGGER IF EXISTS incident_lifecycle_audit_immutable ON incident_lifecycle_audit;
CREATE TRIGGER incident_lifecycle_audit_immutable BEFORE UPDATE OR DELETE ON incident_lifecycle_audit
FOR EACH ROW EXECUTE FUNCTION reject_incident_history_mutation();
DROP TRIGGER IF EXISTS incident_lifecycle_cutover_audit_immutable ON incident_lifecycle_cutover_audit;
CREATE TRIGGER incident_lifecycle_cutover_audit_immutable BEFORE UPDATE OR DELETE ON incident_lifecycle_cutover_audit
FOR EACH ROW EXECUTE FUNCTION reject_incident_history_mutation();
`
