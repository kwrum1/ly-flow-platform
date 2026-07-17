package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type policyRow interface {
	Scan(...any) error
}

func (store *PostgresStore) Create(ctx context.Context, policy PersistedPolicy, event AuditEvent) error {
	document, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO rasp_policy_versions (version, state, document, updated_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, policy.Envelope.Policy.Version, policy.State, document, policy.UpdatedAt)
	if err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrStaleVersion
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy create: %w", err)
	}
	return nil
}

func (store *PostgresStore) Get(ctx context.Context, version uint64) (PersistedPolicy, error) {
	return scanPolicy(store.pool.QueryRow(ctx, `SELECT state, document, updated_at FROM rasp_policy_versions WHERE version=$1`, version))
}

func (store *PostgresStore) Latest(ctx context.Context) (PersistedPolicy, error) {
	return scanPolicy(store.pool.QueryRow(ctx, `SELECT state, document, updated_at FROM rasp_policy_versions ORDER BY version DESC LIMIT 1`))
}

func (store *PostgresStore) Active(ctx context.Context) (PersistedPolicy, error) {
	return scanPolicy(store.pool.QueryRow(ctx, `SELECT state, document, updated_at FROM rasp_policy_versions WHERE state=$1 LIMIT 1`, StateActive))
}

func (store *PostgresStore) Update(ctx context.Context, update PolicyUpdate) error {
	document, err := json.Marshal(update.Policy)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE rasp_policy_versions SET state=$1, document=$2, updated_at=$3 WHERE version=$4 AND state=$5`, update.Policy.State, document, update.Policy.UpdatedAt, update.Policy.Envelope.Policy.Version, update.Expected)
	if err != nil {
		return fmt.Errorf("update policy: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	if err := insertAudit(ctx, tx, update.Event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy update: %w", err)
	}
	return nil
}

func scanPolicy(row policyRow) (PersistedPolicy, error) {
	var state State
	var document []byte
	var updatedAt time.Time
	if err := row.Scan(&state, &document, &updatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return PersistedPolicy{}, ErrNotFound
		}
		return PersistedPolicy{}, fmt.Errorf("scan policy: %w", err)
	}
	var policy PersistedPolicy
	if err := json.Unmarshal(document, &policy); err != nil {
		return PersistedPolicy{}, fmt.Errorf("decode policy: %w", err)
	}
	policy.State, policy.UpdatedAt = state, updatedAt
	return policy, nil
}

func insertAudit(ctx context.Context, tx pgx.Tx, event AuditEvent) error {
	_, err := tx.Exec(ctx, `INSERT INTO rasp_policy_audit (version,event_type,audit_link,detail,occurred_at) VALUES ($1,$2,$3,$4,$5)`, event.Version, event.Type, event.AuditLink, event.Detail, event.OccurredAt)
	if err != nil {
		return fmt.Errorf("insert policy audit: %w", err)
	}
	return nil
}
