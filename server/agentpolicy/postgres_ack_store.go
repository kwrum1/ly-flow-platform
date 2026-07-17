package agentpolicy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (store *PostgresStore) Assignment(ctx context.Context, agentID string) (Assignment, error) {
	var document []byte
	if err := store.pool.QueryRow(ctx, `SELECT document FROM rasp_policy_assignments WHERE agent_id=$1`, agentID).Scan(&document); err != nil {
		if err == pgx.ErrNoRows {
			return Assignment{}, ErrNotFound
		}
		return Assignment{}, fmt.Errorf("scan assignment: %w", err)
	}
	var assignment Assignment
	if err := json.Unmarshal(document, &assignment); err != nil {
		return Assignment{}, fmt.Errorf("decode assignment: %w", err)
	}
	return assignment, nil
}

func (store *PostgresStore) Acknowledge(ctx context.Context, assignment Assignment, event AuditEvent) error {
	document, err := json.Marshal(assignment)
	if err != nil {
		return fmt.Errorf("marshal acknowledgement: %w", err)
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin policy acknowledgement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE rasp_policy_assignments SET ack_version=$1,document=$2,updated_at=$3 WHERE agent_id=$4 AND version=$1`, assignment.ACKVersion, document, assignment.ACKedAt, assignment.AgentID)
	if err != nil {
		return fmt.Errorf("update policy acknowledgement: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrStaleVersion
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy acknowledgement: %w", err)
	}
	return nil
}

func (store *PostgresStore) ACKCount(ctx context.Context, version uint64) (int, error) {
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rasp_policy_assignments WHERE ack_version=$1`, version).Scan(&count); err != nil {
		return 0, fmt.Errorf("count policy acknowledgements: %w", err)
	}
	return count, nil
}
