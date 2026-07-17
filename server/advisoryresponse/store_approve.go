package advisoryresponse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type approvePayload struct {
	AdvisoryID string `json:"advisory_id"`
	Actor      Actor  `json:"actor"`
}

func (store *PostgresStore) Approve(ctx context.Context, command ApprovalCommand) (Advisory, error) {
	id, actor, idempotencyKey := command.AdvisoryID, command.Actor, command.IdempotencyKey
	hash, err := payloadHash(approvePayload{AdvisoryID: id, Actor: actor})
	if err != nil {
		return Advisory{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Advisory{}, fmt.Errorf("begin advisory approval: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := lockIdempotency(ctx, tx, idempotencyKey); err != nil {
		return Advisory{}, err
	}
	if advisory, found, err := replay(ctx, tx, idempotency{Key: idempotencyKey, Hash: hash}); found || err != nil {
		return advisory, err
	}
	advisory, err := scanAdvisory(tx.QueryRow(ctx, `SELECT `+advisoryColumns+` FROM response_advisories WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return Advisory{}, ErrNotFound
	}
	now := store.now().UTC()
	reject := func(reason string) (Advisory, error) {
		return rejectApproval(ctx, tx, auditRecord{AdvisoryID: advisory.ID, IdempotencyKey: idempotencyKey, PayloadHash: hash, Actor: actor, Action: "approve", Outcome: "rejected", Reason: reason, OccurredAt: now})
	}
	if actor.ID == "" || actor.Role != RoleAdmin && actor.Role != RoleAnalyst {
		return reject("forbidden")
	}
	if actor.ID == advisory.RequestedBy {
		return reject("two_person_required")
	}
	if advisory.Algorithm != ActiveAlgorithm || !SupportedAction(advisory.Action) {
		return reject("forbidden")
	}
	var incidentAlgorithm, incidentStatus string
	var incidentLastSeen time.Time
	if err := tx.QueryRow(ctx, `SELECT algorithm_version,status,last_seen FROM incidents WHERE id=$1`, advisory.IncidentID).Scan(&incidentAlgorithm, &incidentStatus, &incidentLastSeen); err != nil {
		return Advisory{}, fmt.Errorf("read approval incident: %w", err)
	}
	if incidentAlgorithm != ActiveAlgorithm || incidentStatus == "closed" || now.Sub(incidentLastSeen) > store.limits.IncidentMaxAge {
		return reject("stale_incident")
	}
	var agentStatus string
	var lastHeartbeat time.Time
	if err := tx.QueryRow(ctx, `SELECT COALESCE(status,'offline'),COALESCE(last_heartbeat,to_timestamp(0)) FROM agents WHERE uuid=$1`, advisory.AgentID).Scan(&agentStatus, &lastHeartbeat); errors.Is(err, pgx.ErrNoRows) {
		return reject("agent_unhealthy")
	} else if err != nil {
		return Advisory{}, fmt.Errorf("read approval Agent: %w", err)
	}
	if agentStatus != "online" || now.Sub(lastHeartbeat) > store.limits.AgentMaxAge {
		return reject("agent_unhealthy")
	}
	if advisory.Verification == nil || !advisory.Verification.Applied || !advisory.Verification.RolledBack || advisory.Verification.Adapter != "in-memory-fake" {
		return reject("verification_required")
	}
	if advisory.Status != StatusPendingApproval {
		return Advisory{}, ErrConflict
	}
	_, err = tx.Exec(ctx, `UPDATE response_advisories SET status=$2,approved_by=$3,approved_at=$4,updated_at=$4 WHERE id=$1`, id, StatusApproved, actor.ID, now)
	if err != nil {
		return Advisory{}, fmt.Errorf("persist advisory approval: %w", err)
	}
	if err := recordAudit(ctx, tx, auditRecord{AdvisoryID: id, IdempotencyKey: idempotencyKey, PayloadHash: hash, Actor: actor, Action: "approve", Outcome: "applied", OccurredAt: now}); err != nil {
		return Advisory{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, fmt.Errorf("commit advisory approval: %w", err)
	}
	return store.Get(ctx, id)
}
