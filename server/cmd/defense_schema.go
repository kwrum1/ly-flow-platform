package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Defense sessions and schedules are additive tables. Nothing here alters or
// drops existing schema: the console may deploy this build on a live database,
// so every statement is guarded with IF NOT EXISTS.
//
// A defense session row is both the runtime state machine and the audit record:
// events is an append-only JSONB array with actor/action/result/detail, and the
// signed RASP policy lifecycle keeps its own audit trail through AuditLink
// "audit://defense/session/<id>".
const defenseSessionsSchema = `CREATE TABLE IF NOT EXISTS defense_sessions (
	id TEXT PRIMARY KEY,
	scope TEXT NOT NULL,
	scope_value TEXT NOT NULL,
	mode TEXT NOT NULL,
	source TEXT NOT NULL DEFAULT 'manual',
	schedule_id TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	created_by TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	starts_at TIMESTAMPTZ NOT NULL,
	dry_run_until TIMESTAMPTZ NOT NULL,
	ends_at TIMESTAMPTZ NOT NULL,
	policy_version BIGINT NOT NULL DEFAULT 0,
	base_version BIGINT NOT NULL DEFAULT 0,
	agent_ids TEXT[] NOT NULL DEFAULT '{}'::text[],
	dry_run_would_block BIGINT NOT NULL DEFAULT 0,
	dry_run_blocked BIGINT NOT NULL DEFAULT 0,
	failure_reason TEXT NOT NULL DEFAULT '',
	stopped_at TIMESTAMPTZ,
	stopped_by TEXT NOT NULL DEFAULT '',
	events JSONB NOT NULL DEFAULT '[]'::jsonb
)`

const defenseSessionsLiveIndex = `CREATE INDEX IF NOT EXISTS idx_defense_sessions_live ON defense_sessions(status) WHERE status IN ('dry_run','active')`

// Only one block policy can be signed and active at a time. The partial unique
// index makes that invariant explicit so two operators (or the scheduler and an
// operator) cannot race into two competing block policies.
const defenseSessionsSingleBlockIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_defense_sessions_single_block ON defense_sessions(mode) WHERE mode = 'block' AND status IN ('dry_run','active')`

const defenseSchedulesSchema = `CREATE TABLE IF NOT EXISTS defense_schedules (
	id TEXT PRIMARY KEY,
	tag TEXT NOT NULL,
	start_time TEXT NOT NULL,
	end_time TEXT NOT NULL,
	priority INTEGER NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	dry_run_seconds INTEGER NOT NULL DEFAULT 300,
	timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
	reason TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	deleted_at TIMESTAMPTZ,
	deleted_by TEXT NOT NULL DEFAULT '',
	events JSONB NOT NULL DEFAULT '[]'::jsonb
)`

const defenseSchedulesEnabledIndex = `CREATE INDEX IF NOT EXISTS idx_defense_schedules_enabled ON defense_schedules(enabled) WHERE deleted_at IS NULL`

// Tag scoped windows resolve agents by agents.tags. The column exists in the
// core schema; this guard keeps tag resolution working on databases created
// before it was introduced. It is additive and best effort.
const defenseAgentsTagsColumn = `ALTER TABLE agents ADD COLUMN IF NOT EXISTS tags TEXT[]`

var defenseSchemaStatements = []string{
	defenseSessionsSchema,
	defenseSessionsLiveIndex,
	defenseSessionsSingleBlockIndex,
	defenseSchedulesSchema,
	defenseSchedulesEnabledIndex,
}

// EnsureDefenseSchema creates the additive defense tables. It is safe to call
// on every start and on a database that already has the tables.
func EnsureDefenseSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("defense: database pool unavailable")
	}
	for _, statement := range defenseSchemaStatements {
		if _, err := pool.Exec(ctx, statement); err != nil {
			return fmt.Errorf("defense schema: %w", err)
		}
	}
	// Best effort: tag scoped schedules must not fail on an older agents table.
	_, _ = pool.Exec(ctx, defenseAgentsTagsColumn)
	return nil
}
