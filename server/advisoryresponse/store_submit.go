package advisoryresponse

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type submitPayload struct {
	CandidateID string `json:"candidate_id"`
	IncidentID  string `json:"incident_id"`
	AgentID     string `json:"agent_id"`
	Algorithm   string `json:"algorithm"`
	Action      Action `json:"action"`
	Target      string `json:"target"`
	Reason      string `json:"reason"`
	Actor       Actor  `json:"actor"`
}

func (store *PostgresStore) Submit(ctx context.Context, command SubmitCommand) (Advisory, error) {
	candidate, actor, idempotencyKey := command.Candidate, command.Actor, command.IdempotencyKey
	if actor.ID == "" || actor.Role != RoleAdmin && actor.Role != RoleAnalyst {
		return Advisory{}, ErrForbidden
	}
	hash, err := payloadHash(submitPayload{
		CandidateID: candidate.id, IncidentID: candidate.incidentID, AgentID: candidate.agentID,
		Algorithm: ActiveAlgorithm, Action: candidate.action, Target: candidate.target,
		Reason: candidate.reason, Actor: actor,
	})
	if err != nil {
		return Advisory{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Advisory{}, fmt.Errorf("begin advisory submit: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockIdempotency(ctx, tx, idempotencyKey); err != nil {
		return Advisory{}, err
	}
	if advisory, found, err := replay(ctx, tx, idempotency{Key: idempotencyKey, Hash: hash}); found || err != nil {
		return advisory, err
	}
	var algorithm string
	if err := tx.QueryRow(ctx, `SELECT algorithm_version FROM incidents WHERE id=$1`, candidate.incidentID).Scan(&algorithm); errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, ErrNotFound
	} else if err != nil {
		return Advisory{}, fmt.Errorf("read advisory incident: %w", err)
	}
	if algorithm != ActiveAlgorithm {
		return Advisory{}, ErrActiveInputRequired
	}
	var agentExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agents WHERE uuid=$1)`, candidate.agentID).Scan(&agentExists); err != nil {
		return Advisory{}, fmt.Errorf("read advisory Agent: %w", err)
	}
	if !agentExists {
		return Advisory{}, ErrNotFound
	}
	now := store.now().UTC()
	_, err = tx.Exec(ctx, `INSERT INTO response_advisories(id,incident_id,agent_id,algorithm_version,action,target,reason,status,requested_by,requested_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, candidate.id, candidate.incidentID, candidate.agentID, ActiveAlgorithm, candidate.action, candidate.target, candidate.reason, StatusPendingVerification, actor.ID, now)
	if err != nil {
		return Advisory{}, fmt.Errorf("insert response advisory: %w", err)
	}
	if err := recordAudit(ctx, tx, auditRecord{AdvisoryID: candidate.id, IdempotencyKey: idempotencyKey, PayloadHash: hash, Actor: actor, Action: "submit", Outcome: "applied", OccurredAt: now}); err != nil {
		return Advisory{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, fmt.Errorf("commit advisory submit: %w", err)
	}
	return store.Get(ctx, candidate.id)
}

func (store *PostgresStore) Get(ctx context.Context, id string) (Advisory, error) {
	advisory, err := scanAdvisory(store.pool.QueryRow(ctx, `SELECT `+advisoryColumns+` FROM response_advisories WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, ErrNotFound
	}
	if err != nil {
		return Advisory{}, fmt.Errorf("get response advisory: %w", err)
	}
	return advisory, nil
}

func (store *PostgresStore) List(ctx context.Context, limit int) ([]Advisory, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := store.pool.Query(ctx, `SELECT `+advisoryColumns+` FROM response_advisories ORDER BY requested_at DESC,id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list response advisories: %w", err)
	}
	defer rows.Close()
	advisories := make([]Advisory, 0)
	for rows.Next() {
		advisory, err := scanAdvisory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan response advisory: %w", err)
		}
		advisories = append(advisories, advisory)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate response advisories: %w", err)
	}
	return advisories, nil
}
