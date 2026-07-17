package agentpolicy

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (store *PostgresStore) EnsureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS rasp_policy_versions (
			version BIGINT PRIMARY KEY,
			state TEXT NOT NULL,
			document JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS rasp_policy_one_active ON rasp_policy_versions ((state)) WHERE state = 'active'`,
		`CREATE TABLE IF NOT EXISTS rasp_policy_assignments (
			agent_id TEXT PRIMARY KEY,
			version BIGINT NOT NULL REFERENCES rasp_policy_versions(version),
			ack_version BIGINT NOT NULL DEFAULT 0,
			document JSONB NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS rasp_policy_assignment_ack ON rasp_policy_assignments (ack_version)`,
		`CREATE TABLE IF NOT EXISTS rasp_policy_audit (
			id BIGSERIAL PRIMARY KEY,
			version BIGINT NOT NULL,
			event_type TEXT NOT NULL,
			audit_link TEXT NOT NULL,
			detail TEXT NOT NULL,
			occurred_at TIMESTAMPTZ NOT NULL
		)`,
	}
	for _, statement := range statements {
		if _, err := store.pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("create RASP policy schema: %w", err)
		}
	}
	return nil
}
