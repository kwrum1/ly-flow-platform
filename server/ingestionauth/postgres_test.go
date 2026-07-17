package ingestionauth

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type recordingSQLExecutor struct {
	query string
	args  []interface{}
}

func (e *recordingSQLExecutor) Exec(_ context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	e.query = query
	e.args = args
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestPostgresAuditPersistsLifecycleEventWithRedaction(t *testing.T) {
	// Given
	executor := &recordingSQLExecutor{}
	audit := NewPostgresAudit(executor)
	event := Event{AgentID: "agent-1", Surface: "grpc.task-result", Outcome: OutcomeRejected, Reason: "Authorization: Bearer secret-value", At: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}

	// When
	err := audit.Record(context.Background(), event)

	// Then
	if err != nil {
		t.Fatalf("record audit: %v", err)
	}
	if len(executor.args) != 5 || executor.args[3] != "redacted security detail" {
		t.Fatalf("persisted audit args = %#v", executor.args)
	}
}
