package advisoryresponse

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool   *pgxpool.Pool
	now    func() time.Time
	limits Limits
}

func NewPostgresStore(pool *pgxpool.Pool, now func() time.Time, limits Limits) *PostgresStore {
	if now == nil {
		now = time.Now
	}
	if limits.IncidentMaxAge <= 0 || limits.AgentMaxAge <= 0 {
		limits = DefaultLimits()
	}
	return &PostgresStore{pool: pool, now: now, limits: limits}
}

func (store *PostgresStore) EnsureSchema(ctx context.Context) error {
	if store == nil || store.pool == nil {
		return fmt.Errorf("advisory response store unavailable")
	}
	if _, err := store.pool.Exec(ctx, advisorySchema); err != nil {
		return fmt.Errorf("apply advisory response migration 20: %w", err)
	}
	return nil
}

const advisorySchema = `
CREATE TABLE IF NOT EXISTS advisory_response_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO advisory_response_schema_migrations(version,name)
VALUES (20,'advisory_response_governance') ON CONFLICT (version) DO NOTHING;

CREATE TABLE IF NOT EXISTS response_advisories (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    agent_id TEXT NOT NULL,
    algorithm_version TEXT NOT NULL CHECK (algorithm_version = 'v2-active'),
    action TEXT NOT NULL CHECK (action IN ('analyst_review','increase_monitoring','collect_forensic_bundle','suggest_waf_or_proxy_acl','suggest_host_isolation')),
    target TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_verification','pending_approval','approved')),
    requested_by TEXT NOT NULL,
    approved_by TEXT NOT NULL DEFAULT '',
    verification_adapter TEXT NOT NULL DEFAULT '',
    verification_applied BOOLEAN NOT NULL DEFAULT FALSE,
    verification_rolled_back BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    requested_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS response_advisories_incident_idx ON response_advisories(incident_id,requested_at DESC);

CREATE TABLE IF NOT EXISTS response_advisory_audit (
    id BIGSERIAL PRIMARY KEY,
    advisory_id TEXT NOT NULL REFERENCES response_advisories(id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('submit','verify','approve')),
    outcome TEXT NOT NULL CHECK (outcome IN ('applied','rejected')),
    reason TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS response_advisory_audit_advisory_idx ON response_advisory_audit(advisory_id,id);

CREATE OR REPLACE FUNCTION reject_response_advisory_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'response advisory audit is immutable';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS response_advisory_audit_immutable ON response_advisory_audit;
CREATE TRIGGER response_advisory_audit_immutable BEFORE UPDATE OR DELETE ON response_advisory_audit
FOR EACH ROW EXECUTE FUNCTION reject_response_advisory_audit_mutation();
`
