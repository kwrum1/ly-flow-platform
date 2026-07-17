package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/security"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func ensureXDRMigrationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, xdrMigrationSchema); err != nil {
		return fmt.Errorf("apply XDR migration schema: %w", err)
	}
	return nil
}

func persistVersionedXDRGraph(ctx context.Context, pool *pgxpool.Pool, snapshot models.VersionedGraphSnapshot) error {
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("validate XDR graph snapshot: %w", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin XDR graph transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var inputChecksum, graphChecksum string
	err = tx.QueryRow(ctx, `SELECT input_checksum, graph_checksum FROM xdr_algorithm_checkpoints
		WHERE tenant_id=$1 AND algorithm_version=$2 FOR UPDATE`, snapshot.TenantID, snapshot.Algorithm.String()).Scan(&inputChecksum, &graphChecksum)
	if err == nil && inputChecksum == snapshot.InputChecksum && graphChecksum == snapshot.GraphChecksum {
		if err := insertXDRScoringDetails(ctx, tx, snapshot.ScoringDetails); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit idempotent %s graph: %w", snapshot.Algorithm, err)
		}
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read %s checkpoint: %w", snapshot.Algorithm, err)
	}
	for _, table := range []string{"xdr_graph_nodes_versioned", "xdr_graph_edges_versioned", "xdr_chain_hypotheses_versioned"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id=$1 AND algorithm_version=$2", snapshot.TenantID, snapshot.Algorithm.String()); err != nil {
			return fmt.Errorf("clear %s %s snapshot: %w", snapshot.Algorithm, table, err)
		}
	}
	if err := insertXDRNodes(ctx, tx, snapshot.Algorithm, snapshot.Nodes); err != nil {
		return err
	}
	if err := insertXDREdges(ctx, tx, snapshot.Algorithm, snapshot.Edges); err != nil {
		return err
	}
	if err := insertXDRHypotheses(ctx, tx, snapshot.Algorithm, snapshot.Hypotheses); err != nil {
		return err
	}
	if err := insertXDRScoringDetails(ctx, tx, snapshot.ScoringDetails); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO xdr_algorithm_checkpoints
		(tenant_id, algorithm_version, input_checksum, graph_checksum, event_count, updated_at)
		VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT (tenant_id, algorithm_version) DO UPDATE SET
		input_checksum=EXCLUDED.input_checksum, graph_checksum=EXCLUDED.graph_checksum, event_count=EXCLUDED.event_count, updated_at=NOW()`,
		snapshot.TenantID, snapshot.Algorithm.String(), snapshot.InputChecksum, snapshot.GraphChecksum, len(snapshot.Nodes)); err != nil {
		return fmt.Errorf("persist %s checkpoint: %w", snapshot.Algorithm, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %s graph: %w", snapshot.Algorithm, err)
	}
	return nil
}

func restoreXDRCheckpointHealth(ctx context.Context, pool *pgxpool.Pool, health *xdrHealthTracker) error {
	rows, err := pool.Query(ctx, `SELECT algorithm_version, input_checksum, graph_checksum, updated_at
		FROM xdr_algorithm_checkpoints WHERE tenant_id=$1`, "default")
	if err != nil {
		return fmt.Errorf("load XDR checkpoints: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rawIdentity, inputChecksum, graphChecksum string
		var updatedAt time.Time
		if err := rows.Scan(&rawIdentity, &inputChecksum, &graphChecksum, &updatedAt); err != nil {
			return fmt.Errorf("scan XDR checkpoint: %w", err)
		}
		identity, err := models.ParseAlgorithmIdentity(rawIdentity)
		if err != nil {
			return fmt.Errorf("parse persisted XDR checkpoint identity: %w", err)
		}
		health.restore(identity, inputChecksum, graphChecksum, updatedAt)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate XDR checkpoints: %w", err)
	}
	return nil
}

func insertXDRNodes(ctx context.Context, tx pgx.Tx, identity models.AlgorithmIdentity, nodes []*models.GraphNodeV2) error {
	for _, node := range nodes {
		if _, err := tx.Exec(ctx, `INSERT INTO xdr_graph_nodes_versioned
			(tenant_id, algorithm_version, node_uid, event_uid, asset_id, ip, hostname, identity, technique_id, tactic_id, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, node.TenantID, identity.String(), node.NodeUID,
			node.EventUID, node.AssetID, node.IP, node.Hostname, node.Identity, node.TechniqueID, node.TacticID, node.CreatedAt); err != nil {
			return fmt.Errorf("insert %s graph node %s: %w", identity, node.NodeUID, err)
		}
	}
	return nil
}

func insertXDREdges(ctx context.Context, tx pgx.Tx, identity models.AlgorithmIdentity, edges []*models.GraphEdgeV2) error {
	for _, edge := range edges {
		evidence, err := json.Marshal(edge.EvidenceEventUIDs)
		if err != nil {
			return fmt.Errorf("encode edge %s evidence: %w", edge.EdgeUID, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO xdr_graph_edges_versioned
			(tenant_id, algorithm_version, edge_uid, from_node_uid, to_node_uid, edge_type, strength, evidence_event_uids, temporal_proximity_secs, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, edge.TenantID, identity.String(), edge.EdgeUID,
			edge.FromNodeUID, edge.ToNodeUID, edge.EdgeType, edge.Strength, evidence, edge.TemporalProximitySecs, edge.CreatedAt); err != nil {
			return fmt.Errorf("insert %s graph edge %s: %w", identity, edge.EdgeUID, err)
		}
	}
	return nil
}

func insertXDRHypotheses(ctx context.Context, tx pgx.Tx, identity models.AlgorithmIdentity, hypotheses []*models.ChainHypothesisV2) error {
	for _, hypothesis := range hypotheses {
		pathNodes, err := json.Marshal(hypothesis.PathNodeUIDs)
		if err != nil {
			return fmt.Errorf("encode hypothesis %s nodes: %w", hypothesis.HypothesisUID, err)
		}
		pathEvidence, err := json.Marshal(hypothesis.PathEvidence)
		if err != nil {
			return fmt.Errorf("encode hypothesis %s evidence: %w", hypothesis.HypothesisUID, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO xdr_chain_hypotheses_versioned
			(tenant_id, algorithm_version, hypothesis_uid, seed_node_uid, path_node_uids, chain_score, severity,
			hypothesis_status, evaluation_version, path_evidence, first_seen, last_seen, traversal_depth, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())`, hypothesis.TenantID, identity.String(),
			hypothesis.HypothesisUID, hypothesis.SeedNodeUID, pathNodes, hypothesis.ChainScore, hypothesis.Severity,
			hypothesis.HypothesisStatus, hypothesis.EvaluationVersion, pathEvidence, hypothesis.FirstSeen, hypothesis.LastSeen,
			hypothesis.TraversalDepth); err != nil {
			return fmt.Errorf("insert %s hypothesis %s: %w", identity, hypothesis.HypothesisUID, err)
		}
	}
	return nil
}

func insertXDRScoringDetails(ctx context.Context, tx pgx.Tx, details []models.ShadowScoringDetail) error {
	for _, detail := range details {
		encoded, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("encode shadow scoring detail %s: %w", detail.DetailUID, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO xdr_scoring_input_details_versioned
			(tenant_id, algorithm_version, feature_version, input_checksum, detail_uid, detail_checksum, detail)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, detail.TenantID, detail.AlgorithmVersion,
			detail.FeatureVersion, detail.InputChecksum, detail.DetailUID, detail.DetailChecksum, encoded); err != nil {
			return fmt.Errorf("insert shadow scoring detail %s: %w", detail.DetailUID, err)
		}
	}
	return nil
}

func checksumXDRGraph(nodes []*models.GraphNodeV2, edges []*models.GraphEdgeV2, hypotheses []*models.ChainHypothesisV2) string {
	rows := make([]string, 0, len(nodes)+len(edges)+len(hypotheses))
	for _, node := range nodes {
		rows = append(rows, strings.Join([]string{"node", node.TenantID, node.NodeUID, node.EventUID, node.AssetID, node.IP, node.Hostname, node.Identity, node.TechniqueID, node.TacticID}, "\x00"))
	}
	for _, edge := range edges {
		rows = append(rows, fmt.Sprintf("edge\x00%s\x00%s\x00%s\x00%s\x00%s\x00%.6f", edge.TenantID, edge.EdgeUID, edge.FromNodeUID, edge.ToNodeUID, edge.EdgeType, edge.Strength))
	}
	for _, hypothesis := range hypotheses {
		rows = append(rows, fmt.Sprintf("chain\x00%s\x00%s\x00%s\x00%.6f\x00%s", hypothesis.TenantID, hypothesis.HypothesisUID, strings.Join(hypothesis.PathNodeUIDs, ","), hypothesis.ChainScore, hypothesis.HypothesisStatus))
	}
	sort.Strings(rows)
	digest := sha256.Sum256([]byte(strings.Join(rows, "\n")))
	return hex.EncodeToString(digest[:])
}

func persistXDRQuarantine(ctx context.Context, pool *pgxpool.Pool, identity models.AlgorithmIdentity, payload []byte, cause error) error {
	var header struct {
		SchemaVersion string `json:"schema_version"`
		Provenance    struct {
			Source contracts.EventSource `json:"source"`
		} `json:"provenance"`
	}
	_ = json.Unmarshal(payload, &header)
	reason := contracts.QuarantineMalformed
	source := header.Provenance.Source
	var quarantine *contracts.QuarantineError
	if errors.As(cause, &quarantine) {
		reason = quarantine.Reason
		if source == "" {
			source = quarantine.Source
		}
	}
	if source == "" {
		source = "canonical"
	}
	redactedRecord := []byte(`{}`)
	var record map[string]interface{}
	if err := json.Unmarshal(payload, &record); err == nil {
		encoded, err := json.Marshal(security.RedactMap(record))
		if err != nil {
			return fmt.Errorf("encode redacted %s quarantine: %w", identity, err)
		}
		redactedRecord = encoded
	}
	digest := sha256.Sum256(payload)
	if _, err := pool.Exec(ctx, `INSERT INTO xdr_input_quarantine
		(algorithm_version, schema_version, reason, source, redacted_record, payload_sha256, quarantined_at)
		VALUES ($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT (algorithm_version, payload_sha256) DO NOTHING`,
		identity.String(), header.SchemaVersion, string(reason), string(source), redactedRecord, hex.EncodeToString(digest[:])); err != nil {
		return fmt.Errorf("persist %s quarantine: %w", identity, err)
	}
	return nil
}

func errorsJoinXDR(primary, persistence error) error {
	return errors.Join(primary, fmt.Errorf("persist quarantine: %w", persistence))
}
