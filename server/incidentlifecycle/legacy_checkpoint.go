package incidentlifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

type durableLegacySnapshot struct {
	Source           string              `json:"source"`
	Checksum         string              `json:"checksum"`
	CapturedAt       time.Time           `json:"captured_at"`
	ImportableFields []string            `json:"importable_fields"`
	Statuses         []LegacyStatus      `json:"statuses"`
	Unrecoverable    SnapshotFieldCounts `json:"unrecoverable"`
	Details          []string            `json:"unrecoverable_details"`
	History          []string            `json:"unrecoverable_history"`
}

func (store *PostgresStore) CheckpointLegacySnapshot(ctx context.Context, statuses []LegacyStatus, source string) (SnapshotReport, error) {
	if err := authorize(Actor{ID: "system:legacy-snapshot", Role: RoleSystem}, ActionSnapshot); err != nil {
		return SnapshotReport{}, err
	}
	snapshot, err := newDurableLegacySnapshot(statuses, source, store.now().UTC())
	report := snapshot.checkpointReport()
	if err != nil {
		return report, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return report, fmt.Errorf("begin legacy incident checkpoint: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, LegacyCutoverName); err != nil {
		return report, fmt.Errorf("lock legacy incident checkpoint: %w", err)
	}
	var cutoverExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_lifecycle_cutover_audit WHERE name=$1)`, LegacyCutoverName).Scan(&cutoverExists); err != nil {
		return report, fmt.Errorf("read legacy incident cutover state: %w", err)
	}
	if cutoverExists {
		return report, fmt.Errorf("legacy incident cutover already complete")
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return report, fmt.Errorf("encode legacy incident checkpoint: %w", err)
	}
	fields, err := json.Marshal(snapshot.ImportableFields)
	if err != nil {
		return report, fmt.Errorf("encode legacy incident importable fields: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO incident_lifecycle_legacy_snapshots
		(name,source,checksum,captured_at,captured,importable_fields,unrecoverable_history,payload)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8::jsonb)
		ON CONFLICT (name) DO UPDATE SET source=EXCLUDED.source,checksum=EXCLUDED.checksum,
		captured_at=EXCLUDED.captured_at,captured=EXCLUDED.captured,importable_fields=EXCLUDED.importable_fields,
		unrecoverable_history=EXCLUDED.unrecoverable_history,payload=EXCLUDED.payload`, LegacyCutoverName, snapshot.Source,
		snapshot.Checksum, snapshot.CapturedAt, len(snapshot.Statuses), fields, snapshot.Unrecoverable.TransitionHistory, payload); err != nil {
		return report, fmt.Errorf("persist legacy incident checkpoint: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("commit legacy incident checkpoint: %w", err)
	}
	return report, nil
}

func (store *PostgresStore) LegacySnapshotAvailable(ctx context.Context) (bool, error) {
	var available bool
	if err := store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_lifecycle_legacy_snapshots WHERE name=$1)`, LegacyCutoverName).Scan(&available); err != nil {
		return false, fmt.Errorf("read durable legacy incident snapshot availability: %w", err)
	}
	return available, nil
}

func newDurableLegacySnapshot(statuses []LegacyStatus, source string, capturedAt time.Time) (durableLegacySnapshot, error) {
	ordered := append([]LegacyStatus(nil), statuses...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].IncidentID < ordered[j].IncidentID })
	snapshot := durableLegacySnapshot{Source: source, CapturedAt: capturedAt, ImportableFields: []string{"status"}, Statuses: ordered, Details: []string{}, History: []string{}}
	for _, status := range ordered {
		snapshot.Unrecoverable.Assignee++
		snapshot.Unrecoverable.Suppression++
		snapshot.Details = append(snapshot.Details,
			status.IncidentID+": assignee unavailable; legacy production incidentStatusStore stored status only",
			status.IncidentID+": suppression unavailable; legacy production incidentStatusStore stored status only")
		if status.Status != StatusOpen {
			snapshot.Unrecoverable.TransitionHistory++
			snapshot.History = append(snapshot.History, status.IncidentID+": prior in-memory transition history unavailable")
			snapshot.Details = append(snapshot.Details, status.IncidentID+": transition history unavailable; legacy production stored only the latest status")
		}
	}
	checksum, err := legacySnapshotChecksum(snapshot)
	if err != nil {
		return snapshot, err
	}
	snapshot.Checksum = checksum
	return snapshot, nil
}

func legacySnapshotChecksum(snapshot durableLegacySnapshot) (string, error) {
	encoded, err := json.Marshal(struct {
		Source           string              `json:"source"`
		CapturedAt       time.Time           `json:"captured_at"`
		ImportableFields []string            `json:"importable_fields"`
		Statuses         []LegacyStatus      `json:"statuses"`
		Unrecoverable    SnapshotFieldCounts `json:"unrecoverable"`
		Details          []string            `json:"unrecoverable_details"`
		History          []string            `json:"unrecoverable_history"`
	}{
		Source: snapshot.Source, CapturedAt: snapshot.CapturedAt, ImportableFields: snapshot.ImportableFields,
		Statuses: snapshot.Statuses, Unrecoverable: snapshot.Unrecoverable, Details: snapshot.Details, History: snapshot.History,
	})
	if err != nil {
		return "", fmt.Errorf("encode legacy incident checkpoint checksum: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (snapshot durableLegacySnapshot) checkpointReport() SnapshotReport {
	return SnapshotReport{Source: snapshot.Source, SnapshotChecksum: snapshot.Checksum, SnapshotCapturedAt: snapshot.CapturedAt,
		ImportableFields: append([]string(nil), snapshot.ImportableFields...), Captured: len(snapshot.Statuses),
		Unmatched: []string{}, UnrecoverableHistory: append([]string(nil), snapshot.History...), Unrecoverable: snapshot.Unrecoverable,
		UnrecoverableDetails: append([]string(nil), snapshot.Details...)}
}
