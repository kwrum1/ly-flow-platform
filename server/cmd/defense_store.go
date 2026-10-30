package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defenseRepository is the persistence surface the defense runtime needs. It is
// an interface so the scheduling/state-machine logic can be unit tested without
// a database.
type defenseRepository interface {
	EnsureSchema(ctx context.Context) error
	CreateSession(ctx context.Context, session DefenseSession) error
	SaveSession(ctx context.Context, session DefenseSession) error
	Session(ctx context.Context, id string) (DefenseSession, error)
	ListSessions(ctx context.Context, statuses []string, limit int) ([]DefenseSession, error)
	LiveBlockSession(ctx context.Context) (DefenseSession, error)

	CreateSchedule(ctx context.Context, schedule DefenseSchedule) error
	SaveSchedule(ctx context.Context, schedule DefenseSchedule) error
	Schedule(ctx context.Context, id string) (DefenseSchedule, error)
	ListSchedules(ctx context.Context, includeDeleted bool) ([]DefenseSchedule, error)

	ResolveTagAgents(ctx context.Context, tag string) ([]string, error)
	ListTags(ctx context.Context) ([]DefenseTag, error)
	DryRunCounts(ctx context.Context, policyVersion uint64, since time.Time) (int64, int64, error)
}

const defenseSessionColumns = `id, scope, scope_value, mode, source, schedule_id, reason, status,
	created_by, created_at, updated_at, starts_at, dry_run_until, ends_at,
	policy_version, base_version, agent_ids, dry_run_would_block, dry_run_blocked,
	failure_reason, stopped_at, stopped_by, events`

const defenseScheduleColumns = `id, tag, start_time, end_time, priority, enabled, dry_run_seconds,
	timezone, reason, created_by, created_at, updated_at, deleted_at, deleted_by, events`

type defenseScanner interface {
	Scan(dest ...any) error
}

type postgresDefenseRepository struct {
	pool *pgxpool.Pool
}

func newPostgresDefenseRepository(pool *pgxpool.Pool) *postgresDefenseRepository {
	return &postgresDefenseRepository{pool: pool}
}

func (repository *postgresDefenseRepository) EnsureSchema(ctx context.Context) error {
	return EnsureDefenseSchema(ctx, repository.pool)
}

func (repository *postgresDefenseRepository) CreateSession(ctx context.Context, session DefenseSession) error {
	events, err := json.Marshal(session.Events)
	if err != nil {
		return fmt.Errorf("defense: encode session events: %w", err)
	}
	_, err = repository.pool.Exec(ctx, `INSERT INTO defense_sessions (`+defenseSessionColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb)`,
		session.ID, session.Scope, session.ScopeValue, session.Mode, session.Source, session.ScheduleID, session.Reason, session.Status,
		session.CreatedBy, session.CreatedAt, session.UpdatedAt, session.StartsAt, session.DryRunUntil, session.EndsAt,
		session.PolicyVersion, session.BaseVersion, defenseStringsOrEmpty(session.AgentIDs), session.DryRunWouldBlock, session.DryRunBlocked,
		session.FailureReason, session.StoppedAt, session.StoppedBy, string(events))
	if err != nil {
		return fmt.Errorf("defense: persist session: %w", err)
	}
	return nil
}

func (repository *postgresDefenseRepository) SaveSession(ctx context.Context, session DefenseSession) error {
	events, err := json.Marshal(session.Events)
	if err != nil {
		return fmt.Errorf("defense: encode session events: %w", err)
	}
	tag, err := repository.pool.Exec(ctx, `UPDATE defense_sessions SET
		status=$2, updated_at=$3, dry_run_until=$4, ends_at=$5, policy_version=$6, base_version=$7,
		agent_ids=$8, dry_run_would_block=$9, dry_run_blocked=$10, failure_reason=$11,
		stopped_at=$12, stopped_by=$13, events=$14::jsonb
		WHERE id=$1`,
		session.ID, session.Status, session.UpdatedAt, session.DryRunUntil, session.EndsAt, session.PolicyVersion, session.BaseVersion,
		defenseStringsOrEmpty(session.AgentIDs), session.DryRunWouldBlock, session.DryRunBlocked, session.FailureReason,
		session.StoppedAt, session.StoppedBy, string(events))
	if err != nil {
		return fmt.Errorf("defense: update session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errDefenseNotFound
	}
	return nil
}

func (repository *postgresDefenseRepository) Session(ctx context.Context, id string) (DefenseSession, error) {
	row := repository.pool.QueryRow(ctx, `SELECT `+defenseSessionColumns+` FROM defense_sessions WHERE id=$1`, id)
	session, err := scanDefenseSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DefenseSession{}, errDefenseNotFound
		}
		return DefenseSession{}, err
	}
	return session, nil
}

func (repository *postgresDefenseRepository) ListSessions(ctx context.Context, statuses []string, limit int) ([]DefenseSession, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := repository.pool.Query(ctx, `SELECT `+defenseSessionColumns+` FROM defense_sessions
		WHERE (cardinality($1::text[]) = 0 OR status = ANY($1::text[]))
		ORDER BY created_at DESC LIMIT $2`, defenseStringsOrEmpty(statuses), limit)
	if err != nil {
		return nil, fmt.Errorf("defense: list sessions: %w", err)
	}
	defer rows.Close()
	sessions := make([]DefenseSession, 0, limit)
	for rows.Next() {
		session, scanErr := scanDefenseSession(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (repository *postgresDefenseRepository) LiveBlockSession(ctx context.Context) (DefenseSession, error) {
	row := repository.pool.QueryRow(ctx, `SELECT `+defenseSessionColumns+` FROM defense_sessions
		WHERE mode='block' AND status IN ('dry_run','active')
		ORDER BY created_at DESC LIMIT 1`)
	session, err := scanDefenseSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DefenseSession{}, errDefenseNotFound
		}
		return DefenseSession{}, err
	}
	return session, nil
}

func (repository *postgresDefenseRepository) CreateSchedule(ctx context.Context, schedule DefenseSchedule) error {
	events, err := json.Marshal(schedule.Events)
	if err != nil {
		return fmt.Errorf("defense: encode schedule events: %w", err)
	}
	_, err = repository.pool.Exec(ctx, `INSERT INTO defense_schedules (`+defenseScheduleColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)`,
		schedule.ID, schedule.Tag, schedule.StartTime, schedule.EndTime, schedule.Priority, schedule.Enabled,
		schedule.DryRunSeconds, schedule.Timezone, schedule.Reason, schedule.CreatedBy, schedule.CreatedAt,
		schedule.UpdatedAt, schedule.DeletedAt, schedule.DeletedBy, string(events))
	if err != nil {
		return fmt.Errorf("defense: persist schedule: %w", err)
	}
	return nil
}

func (repository *postgresDefenseRepository) SaveSchedule(ctx context.Context, schedule DefenseSchedule) error {
	events, err := json.Marshal(schedule.Events)
	if err != nil {
		return fmt.Errorf("defense: encode schedule events: %w", err)
	}
	tag, err := repository.pool.Exec(ctx, `UPDATE defense_schedules SET
		tag=$2, start_time=$3, end_time=$4, priority=$5, enabled=$6, dry_run_seconds=$7,
		timezone=$8, reason=$9, updated_at=$10, deleted_at=$11, deleted_by=$12, events=$13::jsonb
		WHERE id=$1`,
		schedule.ID, schedule.Tag, schedule.StartTime, schedule.EndTime, schedule.Priority, schedule.Enabled,
		schedule.DryRunSeconds, schedule.Timezone, schedule.Reason, schedule.UpdatedAt, schedule.DeletedAt,
		schedule.DeletedBy, string(events))
	if err != nil {
		return fmt.Errorf("defense: update schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errDefenseNotFound
	}
	return nil
}

func (repository *postgresDefenseRepository) Schedule(ctx context.Context, id string) (DefenseSchedule, error) {
	row := repository.pool.QueryRow(ctx, `SELECT `+defenseScheduleColumns+` FROM defense_schedules WHERE id=$1`, id)
	schedule, err := scanDefenseSchedule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DefenseSchedule{}, errDefenseNotFound
		}
		return DefenseSchedule{}, err
	}
	return schedule, nil
}

func (repository *postgresDefenseRepository) ListSchedules(ctx context.Context, includeDeleted bool) ([]DefenseSchedule, error) {
	query := `SELECT ` + defenseScheduleColumns + ` FROM defense_schedules`
	if !includeDeleted {
		query += ` WHERE deleted_at IS NULL`
	}
	query += ` ORDER BY priority DESC, created_at ASC`
	rows, err := repository.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("defense: list schedules: %w", err)
	}
	defer rows.Close()
	schedules := make([]DefenseSchedule, 0)
	for rows.Next() {
		schedule, scanErr := scanDefenseSchedule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

func (repository *postgresDefenseRepository) ResolveTagAgents(ctx context.Context, tag string) ([]string, error) {
	rows, err := repository.pool.Query(ctx, `SELECT uuid FROM agents WHERE $1 = ANY(COALESCE(tags, '{}'::text[])) ORDER BY uuid`, tag)
	if err != nil {
		return nil, fmt.Errorf("defense: resolve tag agents: %w", err)
	}
	defer rows.Close()
	agents := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		agents = append(agents, id)
	}
	return agents, rows.Err()
}

func (repository *postgresDefenseRepository) ListTags(ctx context.Context) ([]DefenseTag, error) {
	rows, err := repository.pool.Query(ctx, `SELECT tag, COUNT(*) FROM (
		SELECT unnest(COALESCE(tags, '{}'::text[])) AS tag FROM agents
	) tagged WHERE tag <> '' GROUP BY tag ORDER BY tag`)
	if err != nil {
		return nil, fmt.Errorf("defense: list tags: %w", err)
	}
	defer rows.Close()
	tags := make([]DefenseTag, 0)
	for rows.Next() {
		var item DefenseTag
		if err := rows.Scan(&item.Tag, &item.Agents); err != nil {
			return nil, err
		}
		tags = append(tags, item)
	}
	return tags, rows.Err()
}

func (repository *postgresDefenseRepository) DryRunCounts(ctx context.Context, policyVersion uint64, since time.Time) (int64, int64, error) {
	row := repository.pool.QueryRow(ctx, `SELECT
		COUNT(*) FILTER (WHERE lower(coalesce(raw_event->>'would_block', raw_event->'details'->>'would_block','false')) IN ('true','1')),
		COUNT(*) FILTER (WHERE lower(coalesce(raw_event->>'blocked', raw_event->'details'->>'blocked','false')) IN ('true','1'))
		FROM threat_events
		WHERE category='rasp'
		  AND coalesce(raw_event->>'policy_version', raw_event->'details'->>'policy_version')=$1
		  AND observed_at >= $2`,
		fmt.Sprintf("%d", policyVersion), since)
	var wouldBlock, blocked int64
	if err := row.Scan(&wouldBlock, &blocked); err != nil {
		return 0, 0, fmt.Errorf("defense: dry-run counts: %w", err)
	}
	return wouldBlock, blocked, nil
}

func scanDefenseSession(scanner defenseScanner) (DefenseSession, error) {
	var session DefenseSession
	var stoppedAt pgtype.Timestamptz
	var eventsRaw []byte
	err := scanner.Scan(
		&session.ID, &session.Scope, &session.ScopeValue, &session.Mode, &session.Source, &session.ScheduleID,
		&session.Reason, &session.Status, &session.CreatedBy, &session.CreatedAt, &session.UpdatedAt,
		&session.StartsAt, &session.DryRunUntil, &session.EndsAt, &session.PolicyVersion, &session.BaseVersion,
		&session.AgentIDs, &session.DryRunWouldBlock, &session.DryRunBlocked, &session.FailureReason,
		&stoppedAt, &session.StoppedBy, &eventsRaw,
	)
	if err != nil {
		return DefenseSession{}, err
	}
	session.StoppedAt = defenseTimePointer(stoppedAt)
	session.Events = decodeDefenseEvents(eventsRaw)
	return session, nil
}

func scanDefenseSchedule(scanner defenseScanner) (DefenseSchedule, error) {
	var schedule DefenseSchedule
	var deletedAt pgtype.Timestamptz
	var eventsRaw []byte
	err := scanner.Scan(
		&schedule.ID, &schedule.Tag, &schedule.StartTime, &schedule.EndTime, &schedule.Priority,
		&schedule.Enabled, &schedule.DryRunSeconds, &schedule.Timezone, &schedule.Reason,
		&schedule.CreatedBy, &schedule.CreatedAt, &schedule.UpdatedAt, &deletedAt, &schedule.DeletedBy, &eventsRaw,
	)
	if err != nil {
		return DefenseSchedule{}, err
	}
	schedule.DeletedAt = defenseTimePointer(deletedAt)
	schedule.Events = decodeDefenseEvents(eventsRaw)
	return schedule, nil
}

func defenseTimePointer(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed := value.Time.UTC()
	return &parsed
}

func decodeDefenseEvents(raw []byte) []DefenseEvent {
	events := make([]DefenseEvent, 0)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &events); err != nil {
			return make([]DefenseEvent, 0)
		}
	}
	return events
}

func defenseStringsOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
