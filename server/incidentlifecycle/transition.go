package incidentlifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func (store *PostgresStore) Apply(ctx context.Context, command Command) (Incident, error) {
	if strings.TrimSpace(command.IncidentID) == "" || strings.TrimSpace(command.IdempotencyKey) == "" {
		return Incident{}, ErrInvalidCommand
	}
	payloadHash := CommandPayloadHash(command)
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Incident{}, fmt.Errorf("begin incident transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, command.IdempotencyKey); err != nil {
		return Incident{}, fmt.Errorf("lock incident idempotency key: %w", err)
	}
	priorIncidentID, priorPayloadHash, priorOutcome, priorReason, err := readIdempotentOutcome(ctx, tx, command.IdempotencyKey)
	if err != nil {
		return Incident{}, err
	}
	if priorOutcome != "" {
		if priorIncidentID != command.IncidentID || priorPayloadHash != payloadHash {
			return Incident{}, ErrConflict
		}
		incident, loadErr := store.loadIncidentTx(ctx, tx, command.IncidentID)
		if loadErr != nil {
			return Incident{}, loadErr
		}
		if err := tx.Commit(ctx); err != nil {
			return Incident{}, fmt.Errorf("commit idempotent incident transition: %w", err)
		}
		if priorOutcome == "rejected" {
			return Incident{}, persistedRejection(priorReason)
		}
		return incident, nil
	}
	now := store.now().UTC()
	incident, err := store.loadIncidentForUpdate(ctx, tx, command.IncidentID)
	if err != nil {
		return Incident{}, err
	}
	reject := func(cause error) (Incident, error) {
		to := command.To
		if to == "" {
			to = incident.Status
		}
		event := AuditEvent{
			IncidentID: incident.ID, IdempotencyKey: command.IdempotencyKey, PayloadHash: payloadHash, Actor: command.Actor,
			Action: command.Action, From: incident.Status, To: to, Outcome: "rejected", Reason: cause.Error(),
			Version: incident.Version, OccurredAt: now,
		}
		if err := insertAudit(ctx, tx, event); err != nil {
			return Incident{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Incident{}, fmt.Errorf("commit rejected incident transition: %w", err)
		}
		return Incident{}, cause
	}
	if err := authorize(command.Actor, command.Action); err != nil {
		return reject(err)
	}
	if command.ExpectedVersion > 0 && command.ExpectedVersion != incident.Version {
		return reject(ErrConflict)
	}
	updated, detail, err := applyCommand(incident, command, now)
	if err != nil {
		return reject(err)
	}
	if updated.Version != incident.Version {
		if err := persistIncidentMutation(ctx, tx, updated); err != nil {
			return Incident{}, err
		}
		if command.Action == ActionSuppress {
			if _, err := tx.Exec(ctx, `INSERT INTO incident_suppressions
				(incident_id,dedup_key,reason,starts_at,expires_at,actor_id,idempotency_key,created_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$4)`, incident.ID, incident.DedupKey, command.Reason, now,
				command.SuppressUntil.UTC(), command.Actor.ID, command.IdempotencyKey); err != nil {
				return Incident{}, fmt.Errorf("persist incident suppression: %w", err)
			}
		}
	}
	to := command.To
	if to == "" {
		to = updated.Status
	}
	event := AuditEvent{
		IncidentID: updated.ID, IdempotencyKey: command.IdempotencyKey, PayloadHash: payloadHash, Actor: command.Actor,
		Action: command.Action, From: incident.Status, To: to, Outcome: "applied", Reason: command.Reason,
		Version: updated.Version, OccurredAt: now, Detail: detail,
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		return Incident{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, fmt.Errorf("commit incident transition: %w", err)
	}
	return updated, nil
}

func applyCommand(incident Incident, command Command, now time.Time) (Incident, map[string]string, error) {
	detail := map[string]string{}
	switch command.Action {
	case ActionTransition:
		if !command.To.Valid() || !LegalTransition(incident.Status, command.To) {
			return Incident{}, nil, ErrIllegalTransition
		}
		if command.To == incident.Status {
			return incident, map[string]string{"result": "already_applied"}, nil
		}
		incident.Status = command.To
		if incident.AcknowledgedAt == nil && (command.To == StatusTriaged || command.To == StatusProcessing) {
			incident.AcknowledgedAt = timePointer(now)
		}
		if incident.ResolvedAt == nil && (command.To == StatusResolved || command.To == StatusClosed) {
			incident.ResolvedAt = timePointer(now)
		} else if command.To == StatusProcessing {
			incident.ResolvedAt = nil
		}
	case ActionAssign:
		assignee := strings.TrimSpace(command.Assignee)
		if assignee == "" {
			return Incident{}, nil, ErrInvalidCommand
		}
		if incident.Assignee == assignee {
			return incident, map[string]string{"result": "already_applied"}, nil
		}
		detail["assignee"] = assignee
		incident.Assignee = assignee
	case ActionSuppress:
		if !command.SuppressUntil.After(now) || strings.TrimSpace(command.Reason) == "" {
			return Incident{}, nil, ErrInvalidCommand
		}
		incident.Suppressed = true
		incident.SuppressedUntil = timePointer(command.SuppressUntil.UTC())
		incident.SuppressionReason = strings.TrimSpace(command.Reason)
		detail["expires_at"] = command.SuppressUntil.UTC().Format(time.RFC3339Nano)
	default:
		return Incident{}, nil, ErrInvalidCommand
	}
	incident.Version++
	incident.UpdatedAt = now
	return incident, detail, nil
}

func persistIncidentMutation(ctx context.Context, tx pgx.Tx, incident Incident) error {
	tag, err := tx.Exec(ctx, `UPDATE incidents SET status=$2,assignee=$3,suppressed_until=$4,suppression_reason=$5,
		acknowledged_at=$6,resolved_at=$7,version=$8,updated_at=$9 WHERE id=$1 AND version=$10`, incident.ID, incident.Status,
		incident.Assignee, incident.SuppressedUntil, incident.SuppressionReason, incident.AcknowledgedAt, incident.ResolvedAt,
		incident.Version, incident.UpdatedAt, incident.Version-1)
	if err != nil {
		return fmt.Errorf("update incident %s: %w", incident.ID, err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func insertAudit(ctx context.Context, tx pgx.Tx, event AuditEvent) error {
	encoded, err := json.Marshal(event.Detail)
	if err != nil {
		return fmt.Errorf("encode incident audit detail: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO incident_lifecycle_audit
		(incident_id,idempotency_key,payload_hash,actor_id,actor_role,action,from_status,to_status,outcome,reason,incident_version,detail,occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, event.IncidentID, event.IdempotencyKey, event.PayloadHash,
		event.Actor.ID, event.Actor.Role, event.Action, event.From, event.To, event.Outcome, event.Reason, event.Version, encoded, event.OccurredAt); err != nil {
		return fmt.Errorf("persist incident audit: %w", err)
	}
	return nil
}

func readIdempotentOutcome(ctx context.Context, tx pgx.Tx, key string) (string, string, string, string, error) {
	var incidentID, payloadHash, outcome, reason string
	err := tx.QueryRow(ctx, `SELECT incident_id,payload_hash,outcome,reason FROM incident_lifecycle_audit WHERE idempotency_key=$1`, key).Scan(&incidentID, &payloadHash, &outcome, &reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", "", nil
	}
	if err != nil {
		return "", "", "", "", fmt.Errorf("read incident idempotency outcome: %w", err)
	}
	return incidentID, payloadHash, outcome, reason, nil
}

func persistedRejection(reason string) error {
	switch reason {
	case ErrForbidden.Error():
		return ErrForbidden
	case ErrConflict.Error():
		return ErrConflict
	case ErrIllegalTransition.Error():
		return ErrIllegalTransition
	default:
		return ErrInvalidCommand
	}
}

func timePointer(value time.Time) *time.Time { return &value }
