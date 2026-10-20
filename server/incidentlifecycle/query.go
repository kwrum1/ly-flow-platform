package incidentlifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const incidentColumns = `id,tenant_id,source_chain_id,algorithm_version,dedup_key,correlation_key,title,summary,severity,status,
	assignee,suppressed_until,suppression_reason,first_seen,last_seen,acknowledge_due_at,resolve_due_at,acknowledged_at,
	resolved_at,version,created_at,updated_at`

type rowScanner interface {
	Scan(...interface{}) error
}

func (store *PostgresStore) Get(ctx context.Context, id string) (Incident, error) {
	incident, err := scanIncident(store.pool.QueryRow(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=$1`, id), store.now())
	if err != nil {
		return Incident{}, err
	}
	incident.Evidence, err = store.loadEvidence(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	incident.Audit, err = store.loadAudit(ctx, id)
	if err != nil {
		return Incident{}, err
	}
	return incident, nil
}

func (store *PostgresStore) List(ctx context.Context, limit, offset int) ([]Incident, int, error) {
	return store.ListFiltered(ctx, limit, offset, "", "")
}

func (store *PostgresStore) ListFiltered(ctx context.Context, limit, offset int, status, severity string) ([]Incident, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	conditions := []string{"1=1"}
	args := make([]interface{}, 0, 4)
	if Status(strings.TrimSpace(status)).Valid() {
		args = append(args, strings.TrimSpace(status))
		conditions = append(conditions, fmt.Sprintf("status=$%d", len(args)))
	}
	if severity = strings.ToLower(strings.TrimSpace(severity)); severity == "critical" || severity == "high" || severity == "medium" || severity == "low" {
		args = append(args, severity)
		conditions = append(conditions, fmt.Sprintf("severity=$%d", len(args)))
	}
	where := " WHERE " + strings.Join(conditions, " AND ")
	var total int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count incidents: %w", err)
	}
	args = append(args, limit, offset)
	rows, err := store.pool.Query(ctx, `SELECT `+incidentColumns+` FROM incidents`+where+
		fmt.Sprintf(" ORDER BY last_seen DESC,id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()
	incidents := make([]Incident, 0, limit)
	for rows.Next() {
		incident, err := scanIncident(rows, store.now())
		if err != nil {
			return nil, 0, err
		}
		incidents = append(incidents, incident)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate incidents: %w", err)
	}
	rows.Close()
	for index := range incidents {
		incidents[index].Evidence, err = store.loadEvidence(ctx, incidents[index].ID)
		if err != nil {
			return nil, 0, err
		}
	}
	return incidents, total, nil
}

func scanIncident(row rowScanner, now time.Time) (Incident, error) {
	var incident Incident
	err := row.Scan(&incident.ID, &incident.TenantID, &incident.SourceChainID, &incident.Algorithm, &incident.DedupKey,
		&incident.CorrelationKey, &incident.Title, &incident.Summary, &incident.Severity, &incident.Status, &incident.Assignee,
		&incident.SuppressedUntil, &incident.SuppressionReason, &incident.FirstSeen, &incident.LastSeen, &incident.AcknowledgeDueAt,
		&incident.ResolveDueAt, &incident.AcknowledgedAt, &incident.ResolvedAt, &incident.Version, &incident.CreatedAt, &incident.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("scan incident: %w", err)
	}
	incident.Suppressed = incident.SuppressedUntil != nil && incident.SuppressedUntil.After(now)
	return incident, nil
}

func (store *PostgresStore) loadIncidentForUpdate(ctx context.Context, tx pgx.Tx, id string) (Incident, error) {
	return scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=$1 FOR UPDATE`, id), store.now())
}

func (store *PostgresStore) loadIncidentTx(ctx context.Context, tx pgx.Tx, id string) (Incident, error) {
	return scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=$1`, id), store.now())
}

func (store *PostgresStore) loadEvidence(ctx context.Context, id string) ([]Evidence, error) {
	rows, err := store.pool.Query(ctx, `SELECT event_uid,source_node_uid,stage,observed_at,evidence FROM incident_evidence_lineage WHERE incident_id=$1 ORDER BY observed_at,event_uid`, id)
	if err != nil {
		return nil, fmt.Errorf("load incident evidence: %w", err)
	}
	defer rows.Close()
	evidence := []Evidence{}
	for rows.Next() {
		var item Evidence
		if err := rows.Scan(&item.EventUID, &item.SourceNodeUID, &item.Stage, &item.ObservedAt, &item.Raw); err != nil {
			return nil, fmt.Errorf("scan incident evidence: %w", err)
		}
		evidence = append(evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate incident evidence: %w", err)
	}
	return evidence, nil
}

func (store *PostgresStore) loadAudit(ctx context.Context, id string) ([]AuditEvent, error) {
	rows, err := store.pool.Query(ctx, `SELECT id,idempotency_key,payload_hash,actor_id,actor_role,action,from_status,to_status,outcome,reason,incident_version,occurred_at FROM incident_lifecycle_audit WHERE incident_id=$1 ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("load incident audit: %w", err)
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		event := AuditEvent{IncidentID: id}
		if err := rows.Scan(&event.ID, &event.IdempotencyKey, &event.PayloadHash, &event.Actor.ID, &event.Actor.Role, &event.Action, &event.From,
			&event.To, &event.Outcome, &event.Reason, &event.Version, &event.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan incident audit: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate incident audit: %w", err)
	}
	return events, nil
}
