package incidentlifecycle

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (store *PostgresStore) importLegacySnapshotTx(ctx context.Context, tx pgx.Tx, snapshot durableLegacySnapshot) (SnapshotReport, error) {
	report := snapshot.checkpointReport()
	for _, legacy := range snapshot.Statuses {
		if strings.TrimSpace(legacy.IncidentID) == "" || !legacy.Status.Valid() {
			report.Unmatched = append(report.Unmatched, legacy.IncidentID)
			report.Unrecoverable.Status++
			report.Unrecoverable.Evidence++
			report.UnrecoverableDetails = append(report.UnrecoverableDetails,
				legacy.IncidentID+": status unavailable; legacy status is invalid",
				legacy.IncidentID+": evidence unavailable; no durable incident matches the legacy status",
			)
			continue
		}
		imported, incident, err := store.importLegacyStatusTx(ctx, tx, legacy)
		if errors.Is(err, ErrNotFound) {
			report.Unmatched = append(report.Unmatched, legacy.IncidentID)
			report.Unrecoverable.Status++
			report.Unrecoverable.Evidence++
			report.UnrecoverableDetails = append(report.UnrecoverableDetails,
				legacy.IncidentID+": status unavailable; no durable incident matches the legacy status",
				legacy.IncidentID+": evidence unavailable; no durable incident matches the legacy status",
			)
			continue
		}
		if err != nil {
			return report, fmt.Errorf("import legacy incident %s: %w", legacy.IncidentID, err)
		}
		if imported {
			report.Imported++
		} else {
			report.AlreadyPersisted++
		}
		report.Recovered.Status++
		var evidenceCount int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM incident_evidence_lineage WHERE incident_id=$1`, incident.ID).Scan(&evidenceCount); err != nil {
			return report, fmt.Errorf("count imported legacy incident %s evidence: %w", legacy.IncidentID, err)
		}
		if evidenceCount == 0 {
			report.Unrecoverable.Evidence++
			report.UnrecoverableDetails = append(report.UnrecoverableDetails, legacy.IncidentID+": evidence unavailable; active XDR snapshot had no lineage")
		} else {
			report.Recovered.Evidence += evidenceCount
		}
	}
	return report, nil
}

func (store *PostgresStore) importLegacyStatusTx(ctx context.Context, tx pgx.Tx, legacy LegacyStatus) (bool, Incident, error) {
	incident, err := store.loadIncidentForUpdate(ctx, tx, legacy.IncidentID)
	if err != nil {
		return false, Incident{}, err
	}
	key := "legacy-snapshot:" + incident.ID + ":" + string(legacy.Status)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_lifecycle_audit WHERE idempotency_key=$1)`, key).Scan(&exists); err != nil {
		return false, Incident{}, fmt.Errorf("read legacy snapshot audit: %w", err)
	}
	if exists || incident.Status == legacy.Status {
		return false, incident, nil
	}
	previous := incident.Status
	incident.Status = legacy.Status
	incident.Version++
	incident.UpdatedAt = store.now().UTC()
	if legacy.Status == StatusResolved || legacy.Status == StatusClosed {
		incident.ResolvedAt = timePointer(incident.UpdatedAt)
	}
	if err := persistIncidentMutation(ctx, tx, incident); err != nil {
		return false, Incident{}, err
	}
	event := AuditEvent{
		IncidentID: incident.ID, IdempotencyKey: key, Actor: Actor{ID: "system:legacy-snapshot", Role: RoleSystem},
		Action: ActionSnapshot, From: previous, To: incident.Status, Outcome: "applied",
		Reason: "prior in-memory transition history unavailable", Version: incident.Version, OccurredAt: incident.UpdatedAt,
		Detail: map[string]string{
			"legacy_source":        "server/cmd.incidentStatusStore sync.Map",
			"recovered_fields":     "status",
			"unrecoverable_fields": "assignee,suppression,prior_transition_history",
		},
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		return false, Incident{}, err
	}
	return true, incident, nil
}
