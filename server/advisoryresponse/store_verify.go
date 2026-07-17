package advisoryresponse

import (
	"context"
	"fmt"
)

type verifyPayload struct {
	AdvisoryID string `json:"advisory_id"`
	Actor      Actor  `json:"actor"`
}

func (store *PostgresStore) Verify(ctx context.Context, command VerifyCommand) (Advisory, error) {
	id, actor, idempotencyKey, adapter := command.AdvisoryID, command.Actor, command.IdempotencyKey, command.Adapter
	if actor.ID == "" || actor.Role != RoleVerifier || adapter == nil {
		return Advisory{}, ErrForbidden
	}
	hash, err := payloadHash(verifyPayload{AdvisoryID: id, Actor: actor})
	if err != nil {
		return Advisory{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Advisory{}, fmt.Errorf("begin advisory verification: %w", err)
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
	if advisory.Status != StatusPendingVerification {
		return Advisory{}, ErrConflict
	}
	candidate, err := NewCandidate(CandidateInput{
		ID: advisory.ID, IncidentID: advisory.IncidentID, AgentID: advisory.AgentID,
		Algorithm: advisory.Algorithm, Action: advisory.Action, Target: advisory.Target, Reason: advisory.Reason,
	})
	if err != nil {
		return Advisory{}, err
	}
	verification, err := adapter.Simulate(ctx, candidate)
	if err != nil || verification.Adapter != "in-memory-fake" || !verification.Applied || !verification.RolledBack {
		return Advisory{}, ErrVerificationFailed
	}
	now := store.now().UTC()
	_, err = tx.Exec(ctx, `UPDATE response_advisories SET status=$2,verification_adapter=$3,verification_applied=$4,verification_rolled_back=$5,verified_at=$6,updated_at=$6 WHERE id=$1`, id, StatusPendingApproval, verification.Adapter, verification.Applied, verification.RolledBack, now)
	if err != nil {
		return Advisory{}, fmt.Errorf("persist advisory verification: %w", err)
	}
	if err := recordAudit(ctx, tx, auditRecord{AdvisoryID: id, IdempotencyKey: idempotencyKey, PayloadHash: hash, Actor: actor, Action: "verify", Outcome: "applied", OccurredAt: now}); err != nil {
		return Advisory{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, fmt.Errorf("commit advisory verification: %w", err)
	}
	return store.Get(ctx, id)
}
