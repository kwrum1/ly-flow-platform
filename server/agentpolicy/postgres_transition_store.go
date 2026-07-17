package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"
)

func (store *PostgresStore) Promote(ctx context.Context, candidate PersistedPolicy, event AuditEvent) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy promotion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE rasp_policy_versions SET state=$1, updated_at=$2 WHERE state=$3`, StateSuperseded, candidate.UpdatedAt, StateActive); err != nil {
		return fmt.Errorf("supersede active policy: %w", err)
	}
	document, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("marshal promoted policy: %w", err)
	}
	tag, err := tx.Exec(ctx, `UPDATE rasp_policy_versions SET state=$1, document=$2, updated_at=$3 WHERE version=$4 AND state=$5`, StateActive, document, candidate.UpdatedAt, candidate.Envelope.Policy.Version, StateCanary)
	if err != nil {
		return fmt.Errorf("activate policy: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy promotion: %w", err)
	}
	return nil
}

func (store *PostgresStore) Rollback(ctx context.Context, change RollbackChange) error {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy rollback: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	currentDocument, err := json.Marshal(change.Current)
	if err != nil {
		return fmt.Errorf("marshal rolled back policy: %w", err)
	}
	targetDocument, err := json.Marshal(change.Target)
	if err != nil {
		return fmt.Errorf("marshal rollback target: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE rasp_policy_versions SET state=$1, document=$2, updated_at=$3 WHERE version=$4`, change.Current.State, currentDocument, change.Current.UpdatedAt, change.Current.Envelope.Policy.Version); err != nil {
		return fmt.Errorf("mark policy rolled back: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE rasp_policy_versions SET state=$1, document=$2, updated_at=$3 WHERE version=$4`, change.Target.State, targetDocument, change.Target.UpdatedAt, change.Target.Envelope.Policy.Version); err != nil {
		return fmt.Errorf("activate rollback target: %w", err)
	}
	if err := insertAudit(ctx, tx, change.Event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy rollback: %w", err)
	}
	return nil
}

func (store *PostgresStore) Assign(ctx context.Context, assignment Assignment, event AuditEvent) error {
	document, err := json.Marshal(assignment)
	if err != nil {
		return fmt.Errorf("marshal assignment: %w", err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy assignment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO rasp_policy_assignments (agent_id,version,ack_version,document,updated_at) VALUES ($1,$2,0,$3,$4) ON CONFLICT (agent_id) DO UPDATE SET version=EXCLUDED.version,ack_version=0,document=EXCLUDED.document,updated_at=EXCLUDED.updated_at`, assignment.AgentID, assignment.Envelope.Policy.Version, document, assignment.AssignedAt)
	if err != nil {
		return fmt.Errorf("upsert assignment: %w", err)
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy assignment: %w", err)
	}
	return nil
}
