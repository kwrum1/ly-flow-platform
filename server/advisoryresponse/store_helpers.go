package advisoryresponse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const advisoryColumns = `id,incident_id,agent_id,algorithm_version,action,target,reason,status,requested_by,approved_by,verification_adapter,verification_applied,verification_rolled_back,verified_at,requested_at,approved_at,updated_at`

type rowScanner interface {
	Scan(...any) error
}

func scanAdvisory(row rowScanner) (Advisory, error) {
	var advisory Advisory
	var action, status string
	var adapter string
	var applied, rolledBack bool
	var verifiedAt *time.Time
	err := row.Scan(&advisory.ID, &advisory.IncidentID, &advisory.AgentID, &advisory.Algorithm, &action, &advisory.Target, &advisory.Reason, &status, &advisory.RequestedBy, &advisory.ApprovedBy, &adapter, &applied, &rolledBack, &verifiedAt, &advisory.RequestedAt, &advisory.ApprovedAt, &advisory.UpdatedAt)
	if err != nil {
		return Advisory{}, err
	}
	advisory.Action = Action(action)
	advisory.Status = Status(status)
	if verifiedAt != nil {
		advisory.Verification = &Verification{Adapter: adapter, Applied: applied, RolledBack: rolledBack, VerifiedAt: *verifiedAt}
	}
	return advisory, nil
}

type commandPayload interface {
	submitPayload | verifyPayload | approvePayload
}

func payloadHash[T commandPayload](value T) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode advisory command: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func lockIdempotency(ctx context.Context, tx pgx.Tx, key string) error {
	if key == "" {
		return ErrConflict
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
		return fmt.Errorf("lock advisory idempotency: %w", err)
	}
	return nil
}

type idempotency struct {
	Key  string
	Hash string
}

func replay(ctx context.Context, tx pgx.Tx, request idempotency) (Advisory, bool, error) {
	var existingHash, advisoryID, outcome, reason string
	err := tx.QueryRow(ctx, `SELECT payload_hash,advisory_id,outcome,reason FROM response_advisory_audit WHERE idempotency_key=$1`, request.Key).Scan(&existingHash, &advisoryID, &outcome, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, false, nil
	}
	if err != nil {
		return Advisory{}, false, fmt.Errorf("read advisory idempotency: %w", err)
	}
	if existingHash != request.Hash {
		return Advisory{}, true, ErrConflict
	}
	advisory, err := scanAdvisory(tx.QueryRow(ctx, `SELECT `+advisoryColumns+` FROM response_advisories WHERE id=$1`, advisoryID))
	if err != nil {
		return Advisory{}, true, fmt.Errorf("read replayed advisory: %w", err)
	}
	if outcome == "rejected" {
		return Advisory{}, true, rejectionError(reason)
	}
	return advisory, true, nil
}

func rejectionError(reason string) error {
	switch reason {
	case "two_person_required":
		return ErrTwoPersonRequired
	case "stale_incident":
		return ErrStaleIncident
	case "agent_unhealthy":
		return ErrAgentUnhealthy
	case "verification_required":
		return ErrVerificationRequired
	case "forbidden":
		return ErrForbidden
	default:
		return ErrConflict
	}
}

type auditRecord struct {
	AdvisoryID     string
	IdempotencyKey string
	PayloadHash    string
	Actor          Actor
	Action         string
	Outcome        string
	Reason         string
	OccurredAt     time.Time
}

func recordAudit(ctx context.Context, tx pgx.Tx, record auditRecord) error {
	_, err := tx.Exec(ctx, `INSERT INTO response_advisory_audit(advisory_id,idempotency_key,payload_hash,actor_id,actor_role,action,outcome,reason,occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.AdvisoryID, record.IdempotencyKey, record.PayloadHash, record.Actor.ID, record.Actor.Role, record.Action, record.Outcome, record.Reason, record.OccurredAt)
	if err != nil {
		return fmt.Errorf("record advisory audit: %w", err)
	}
	return nil
}

func rejectApproval(ctx context.Context, tx pgx.Tx, record auditRecord) (Advisory, error) {
	if err := recordAudit(ctx, tx, record); err != nil {
		return Advisory{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, fmt.Errorf("commit rejected advisory approval: %w", err)
	}
	return Advisory{}, rejectionError(record.Reason)
}
