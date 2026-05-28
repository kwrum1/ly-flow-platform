package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type edgeCandidate struct {
	from, to int
	edgeType string
	strength float64
	evidence  []string
	proximity int
}

func buildGraphEdges(ctx context.Context, events []*models.CanonicalEventV2, config *Config) ([]*models.GraphNodeV2, []*models.GraphEdgeV2) {
	nodes := make([]*models.GraphNodeV2, 0, len(events))
	for _, ev := range events {
		node := &models.GraphNodeV2{
			TenantID:    ev.TenantID,
			NodeUID:     "node-" + ev.EventUID,
			EventUID:    ev.EventUID,
			IP:          firstOrEmpty(ev.NormalizedSrcIP, ev.NormalizedDstIP),
			Hostname:    ev.VictimAsset,
			Identity:    ev.ActorIdentity,
			TechniqueID: ev.TechniqueID,
			TacticID:    ev.TacticID,
			CreatedAt:   time.Now().UTC(),
		}
		if ev.HostID != "" {
			node.AssetID = ev.HostID
		} else if ev.AgentID != "" {
			node.AssetID = ev.AgentID
		}
		nodes = append(nodes, node)
	}

	if len(events) < 2 {
		return nodes, nil
	}

	candidates := []*edgeCandidate{}

	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			a, b := events[i], events[j]
			cand := classifyEdge(a, b)
			if cand != nil {
				cand.from, cand.to = i, j
				candidates = append(candidates, cand)
			}
		}
	}

	edges := make([]*models.GraphEdgeV2, 0, len(candidates))
	for _, cand := range candidates {
		edge := &models.GraphEdgeV2{
			TenantID:             nodes[cand.from].TenantID,
			EdgeUID:              fmt.Sprintf("edge-%s-%s-%s", nodes[cand.from].NodeUID, nodes[cand.to].NodeUID, cand.edgeType),
			FromNodeUID:          nodes[cand.from].NodeUID,
			ToNodeUID:            nodes[cand.to].NodeUID,
			EdgeType:             cand.edgeType,
			Strength:             cand.strength,
			EvidenceEventUIDs:    cand.evidence,
			TemporalProximitySecs: cand.proximity,
			CreatedAt:            time.Now().UTC(),
		}
		edges = append(edges, edge)
	}

	return nodes, edges
}

func classifyEdge(a, b *models.CanonicalEventV2) *edgeCandidate {
	sameHost := a.AgentID != "" && a.AgentID == b.AgentID
	sameIdentity := a.ActorIdentity != "" && a.ActorIdentity == b.ActorIdentity
	sameProcess := strings.EqualFold(a.EventType, b.EventType) && sameHost && sameIdentity
	timeDiff := int(b.ObservedAt.Sub(a.ObservedAt).Seconds())
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}

	if sameProcess {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeSameProcess,
			strength:  models.EdgeStrengthStrong,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	if sameIdentity && sameHost {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeSameIdentity,
			strength:  models.EdgeStrengthModerate,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	if sameHost && timeDiff < 600 {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeSameHost,
			strength:  models.EdgeStrengthModerate,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	if sameIdentity && timeDiff < 600 {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeCredentialReuse,
			strength:  models.EdgeStrengthModerate,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	if !sameHost {
		isLateral := false
		if strings.EqualFold(a.StageHint, models.StageCredentialAccess) && strings.EqualFold(b.StageHint, models.StageLateralMovement) {
			isLateral = true
		}
		if strings.EqualFold(a.StageHint, models.StageLateralMovement) && strings.EqualFold(b.StageHint, models.StageExecution) {
			isLateral = true
		}
		if sameIdentity {
			isLateral = true
		}
		if isLateral {
			str := models.EdgeStrengthModerate
			if sameIdentity {
				str = models.EdgeStrengthStrong
			}
			return &edgeCandidate{
				edgeType:  models.EdgeTypeLateralMovement,
				strength:  str,
				evidence:  []string{a.EventUID, b.EventUID},
				proximity: timeDiff,
			}
		}
	}

	sameSrcIP := a.NormalizedSrcIP != "" && a.NormalizedSrcIP == b.NormalizedSrcIP
	if sameSrcIP && !sameHost {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeWeakSameIP,
			strength:  models.EdgeStrengthWeak,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	stageOrderDiff := models.StageOrder(b.StageHint) - models.StageOrder(a.StageHint)
	if sameHost && stageOrderDiff > 0 && timeDiff < 3600 {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeAttackTransition,
			strength:  models.EdgeStrengthModerate,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	if a.VictimAsset != "" && a.VictimAsset == b.VictimAsset && b.ObservedAt.After(a.ObservedAt) && timeDiff < 7200 {
		return &edgeCandidate{
			edgeType:  models.EdgeTypeAttackTransition,
			strength:  models.EdgeStrengthModerate,
			evidence:  []string{a.EventUID, b.EventUID},
			proximity: timeDiff,
		}
	}

	return nil
}

func persistGraphNodes(ctx context.Context, nodes []*models.GraphNodeV2, config *Config) error {
	if config.DBPool == nil || len(nodes) == 0 {
		return nil
	}
	for _, node := range nodes {
		_, err := config.DBPool.Exec(ctx,
			`INSERT INTO xdr_graph_nodes (tenant_id, node_uid, event_uid, asset_id, ip, hostname, identity, technique_id, tactic_id, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			 ON CONFLICT (tenant_id, node_uid) DO UPDATE SET ip=EXCLUDED.ip, hostname=EXCLUDED.hostname, created_at=NOW()`,
			node.TenantID, node.NodeUID, node.EventUID, node.AssetID, node.IP, node.Hostname, node.Identity, node.TechniqueID, node.TacticID, node.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert graph node %s: %w", node.NodeUID, err)
		}
	}
	return nil
}

func persistGraphEdges(ctx context.Context, edges []*models.GraphEdgeV2, config *Config) error {
	if config.DBPool == nil || len(edges) == 0 {
		return nil
	}
	for _, edge := range edges {
		evidenceJSON, _ := json.Marshal(edge.EvidenceEventUIDs)
		_, err := config.DBPool.Exec(ctx,
			`INSERT INTO xdr_graph_edges (tenant_id, edge_uid, from_node_uid, to_node_uid, edge_type, strength, evidence_event_uids, temporal_proximity_secs, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			 ON CONFLICT (tenant_id, edge_uid) DO UPDATE SET strength=EXCLUDED.strength, created_at=NOW()`,
			edge.TenantID, edge.EdgeUID, edge.FromNodeUID, edge.ToNodeUID, edge.EdgeType, edge.Strength, evidenceJSON, edge.TemporalProximitySecs, edge.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert graph edge %s: %w", edge.EdgeUID, err)
		}
	}
	return nil
}
