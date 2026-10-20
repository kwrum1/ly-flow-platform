package incidentlifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (store *PostgresStore) SyncActive(ctx context.Context, snapshot ActiveSnapshot) (SyncReport, error) {
	report := SyncReport{}
	now := store.now().UTC()
	for _, candidate := range snapshot.candidates {
		created, evidenceAdded, err := store.syncCandidate(ctx, candidate, now)
		if err != nil {
			return SyncReport{}, err
		}
		if created {
			report.Created++
		} else {
			report.Updated++
		}
		report.EvidenceAdded += evidenceAdded
	}
	return report, nil
}

func (store *PostgresStore) syncCandidate(ctx context.Context, candidate Candidate, now time.Time) (bool, int, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("begin active incident sync: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	dedupKey := DedupKey("default", candidate)
	ackDue, resolveDue := slaDeadlines(candidate.FirstSeen, candidate.Severity)
	// The graph can legitimately re-key an active chain while an older row
	// still owns the same deterministic incident id. Resolve the existing row
	// by dedup_key first, then fall back to id, and update that row instead of
	// attempting a second primary-key insert.
	var existingID string
	if err := tx.QueryRow(ctx, `SELECT COALESCE((
			SELECT id FROM incidents
			WHERE tenant_id='default' AND (id=$1 OR dedup_key=$2)
			ORDER BY (dedup_key=$2) DESC, (id=$1) DESC
			LIMIT 1
		), '')`, candidate.IncidentID, dedupKey).Scan(&existingID); err != nil {
		return false, 0, fmt.Errorf("resolve active incident %s: %w", candidate.IncidentID, err)
	}
	if existingID != "" {
		candidate.IncidentID = existingID
	}
	var incidentID string
	var created bool
	err = tx.QueryRow(ctx, `INSERT INTO incidents
		(id,tenant_id,source_chain_id,algorithm_version,dedup_key,correlation_key,title,summary,severity,status,
		 first_seen,last_seen,acknowledge_due_at,resolve_due_at,version,created_at,updated_at)
		VALUES ($1,'default',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14,$14)
		ON CONFLICT (id) DO UPDATE SET
		 dedup_key=EXCLUDED.dedup_key,source_chain_id=EXCLUDED.source_chain_id,
		 correlation_key=EXCLUDED.correlation_key,title=EXCLUDED.title,
		 summary=EXCLUDED.summary,severity=EXCLUDED.severity,first_seen=LEAST(incidents.first_seen,EXCLUDED.first_seen),
		 last_seen=GREATEST(incidents.last_seen,EXCLUDED.last_seen),
		 acknowledge_due_at=LEAST(incidents.acknowledge_due_at,EXCLUDED.acknowledge_due_at),
		 resolve_due_at=LEAST(incidents.resolve_due_at,EXCLUDED.resolve_due_at),updated_at=EXCLUDED.updated_at
		RETURNING id,(xmax = 0)`, candidate.IncidentID, candidate.SourceChainID, ActiveAlgorithm, dedupKey,
		candidate.CorrelationKey, candidate.Title, candidate.Summary, normalizeSeverity(candidate.Severity), StatusOpen,
		candidate.FirstSeen.UTC(), candidate.LastSeen.UTC(), ackDue, resolveDue, now).Scan(&incidentID, &created)
	if err != nil {
		return false, 0, fmt.Errorf("upsert active incident %s: %w", candidate.IncidentID, err)
	}
	if created {
		if _, err := tx.Exec(ctx, `INSERT INTO incident_lifecycle_audit
			(incident_id,idempotency_key,actor_id,actor_role,action,from_status,to_status,outcome,reason,incident_version,detail,occurred_at)
			VALUES ($1,$2,'system:xdr','system',$3,$4,$4,'applied','v2-active incident created',1,'{}',$5)
			ON CONFLICT (idempotency_key) DO NOTHING`, incidentID, "create:"+dedupKey, ActionCreate, StatusOpen, now); err != nil {
			return false, 0, fmt.Errorf("audit active incident %s creation: %w", incidentID, err)
		}
	}
	evidenceAdded := 0
	for _, evidence := range candidate.Evidence {
		if strings.TrimSpace(evidence.EventUID) == "" || evidence.ObservedAt.IsZero() {
			return false, 0, fmt.Errorf("incident %s evidence: %w", incidentID, ErrInvalidCommand)
		}
		encoded := evidence.Raw
		if len(encoded) == 0 {
			encoded, err = json.Marshal(evidence)
			if err != nil {
				return false, 0, fmt.Errorf("encode evidence %s: %w", evidence.EventUID, err)
			}
		}
		digest := sha256.Sum256(encoded)
		tag, err := tx.Exec(ctx, `INSERT INTO incident_evidence_lineage
			(incident_id,source_chain_id,algorithm_version,event_uid,source_node_uid,stage,observed_at,evidence,evidence_checksum,recorded_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`, incidentID, candidate.SourceChainID,
			ActiveAlgorithm, evidence.EventUID, evidence.SourceNodeUID, evidence.Stage, evidence.ObservedAt.UTC(), encoded,
			hex.EncodeToString(digest[:]), now)
		if err != nil {
			return false, 0, fmt.Errorf("persist incident %s evidence %s: %w", incidentID, evidence.EventUID, err)
		}
		evidenceAdded += int(tag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		return false, 0, fmt.Errorf("commit active incident %s sync: %w", incidentID, err)
	}
	return created, evidenceAdded, nil
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return "low"
	}
}

func slaDeadlines(firstSeen time.Time, severity string) (time.Time, time.Time) {
	ack, resolve := 24*time.Hour, 72*time.Hour
	switch normalizeSeverity(severity) {
	case "critical":
		ack, resolve = 15*time.Minute, 4*time.Hour
	case "high":
		ack, resolve = 30*time.Minute, 8*time.Hour
	case "medium":
		ack, resolve = 4*time.Hour, 24*time.Hour
	case "low":
	}
	return firstSeen.UTC().Add(ack), firstSeen.UTC().Add(resolve)
}
