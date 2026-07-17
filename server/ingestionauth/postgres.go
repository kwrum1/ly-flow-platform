package ingestionauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

type SQLExecutor interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
}

type PostgresAudit struct{ executor SQLExecutor }

func NewPostgresAudit(executor SQLExecutor) *PostgresAudit {
	return &PostgresAudit{executor: executor}
}

func (a *PostgresAudit) EnsureSchema(ctx context.Context) error {
	if a == nil || a.executor == nil {
		return ErrAuditUnavailable
	}
	_, err := a.executor.Exec(ctx, `CREATE TABLE IF NOT EXISTS agent_ingestion_audit (
		id BIGSERIAL PRIMARY KEY,
		agent_id TEXT NOT NULL,
		surface TEXT NOT NULL,
		outcome TEXT NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
		occurred_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("ensure ingestion audit schema: %w", err)
	}
	return nil
}

func (a *PostgresAudit) Record(ctx context.Context, event Event) error {
	if a == nil || a.executor == nil {
		return ErrAuditUnavailable
	}
	_, err := a.executor.Exec(ctx, `INSERT INTO agent_ingestion_audit (agent_id, surface, outcome, reason, occurred_at) VALUES ($1,$2,$3,$4,$5)`, event.AgentID, event.Surface, event.Outcome, auditReason(event.Reason), event.At)
	if err != nil {
		return fmt.Errorf("persist ingestion audit: %w", err)
	}
	return nil
}

func auditReason(reason string) string {
	trimmed := strings.TrimSpace(reason)
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "bearer ") || strings.Contains(lower, "authorization") || strings.Contains(lower, "agent_key") {
		return "redacted security detail"
	}
	if len(trimmed) > 256 {
		return trimmed[:256]
	}
	return trimmed
}
