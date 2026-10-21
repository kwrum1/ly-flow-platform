package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type incidentSnapshotState struct {
	report incidentlifecycle.SnapshotReport
	err    error
}

func newIncidentLifecycleRuntime(ctx context.Context, cfg *Config) (*incidentlifecycle.PostgresStore, error) {
	store := incidentlifecycle.NewPostgresStore(cfg.DBPool, time.Now)
	if err := store.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func initializeIncidentLifecycleRuntime(ctx context.Context, cfg *Config) error {
	if cfg == nil || cfg.DBPool == nil {
		return fmt.Errorf("incident lifecycle database unavailable")
	}
	store, err := newIncidentLifecycleRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	cfg.IncidentCheckpoint = store
	if cfg.IncidentSnapshot == nil {
		cfg.IncidentSnapshot = &incidentSnapshotState{}
	}
	if cfg.IncidentLegacyMode {
		cfg.Incidents = store
		return nil
	}
	persistedReport, cutoverComplete, err := store.LegacyCutover(ctx)
	if err != nil {
		return err
	}
	if !cutoverComplete {
		available, snapshotErr := store.LegacySnapshotAvailable(ctx)
		if snapshotErr != nil {
			return snapshotErr
		}
		if !available {
			return incidentlifecycle.ErrLegacySnapshotRequired
		}
	}
	if cfg.XDRGraph != nil && cfg.XDRInput != nil {
		active, activeErr := xdrActiveChainsResponse(ctx, cfg, 1000)
		if activeErr != nil {
			log.Printf("incident lifecycle startup active sync unavailable: %v", activeErr)
		} else if syncErr := syncActiveIncidentStore(ctx, store, active); syncErr != nil {
			log.Printf("incident lifecycle startup active sync failed: %v", syncErr)
		} else if syncErr := syncTrafficIncidentCandidatesWithStore(ctx, cfg, store); syncErr != nil {
			log.Printf("incident lifecycle startup traffic sync failed: %v", syncErr)
		}
	}
	if cutoverComplete {
		cfg.IncidentSnapshot.report = persistedReport
		cfg.Incidents = store
		return nil
	}
	report, err := store.ImportLegacyCutover(ctx)
	cfg.IncidentSnapshot.report = report
	cfg.IncidentSnapshot.err = err
	if err != nil {
		return fmt.Errorf("incident lifecycle legacy cutover: %w", err)
	}
	cfg.Incidents = store
	return nil
}

func syncActiveIncidentLifecycle(ctx context.Context, cfg *Config, input xdrIncidentInput) error {
	if cfg == nil || cfg.Incidents == nil {
		return fmt.Errorf("persistent incident lifecycle unavailable")
	}
	if err := syncActiveIncidentStore(ctx, cfg.Incidents, input); err != nil {
		return err
	}
	if err := syncTrafficIncidentCandidates(ctx, cfg); err != nil {
		log.Printf("traffic incident candidate sync failed: %v", err)
	}
	return nil
}

func syncActiveIncidentStore(ctx context.Context, store *incidentlifecycle.PostgresStore, input xdrIncidentInput) error {
	candidates := make([]incidentlifecycle.Candidate, 0)
	for _, chain := range input.incidentChains() {
		if chain.EventCount < 2 || len(uniqueStrings(chain.Stages)) < 2 || chain.CandidateOnly && chain.PathEvidence == nil {
			continue
		}
		if !incidentPathHasStrongEdge(chain.PathEvidence) {
			continue
		}
		row := chain.jsonRow()
		evidence := make([]incidentlifecycle.Evidence, 0)
		displayEvidence := make(map[string]map[string]interface{}, len(chain.Evidence))
		for _, item := range chain.Evidence {
			value := asMap(item)
			if eventUID := xdrPickString(value, "id", "event_id"); eventUID != "" {
				displayEvidence[eventUID] = value
			}
		}
		if chain.PathEvidence != nil {
			for _, entry := range chain.PathEvidence.Timeline {
				eventUID := strings.TrimPrefix(entry.NodeUID, "node-")
				rawValue := map[string]interface{}{"path": entry}
				for key, value := range displayEvidence[eventUID] {
					rawValue[key] = value
				}
				raw, err := json.Marshal(rawValue)
				if err != nil {
					return fmt.Errorf("encode incident lineage %s: %w", chain.ID, err)
				}
				evidence = append(evidence, incidentlifecycle.Evidence{
					EventUID: eventUID, SourceNodeUID: entry.NodeUID,
					Stage: entry.Stage, ObservedAt: entry.ObservedAt, Raw: raw,
				})
			}
		}
		firstSeen, lastSeen := parseXDRTime(chain.FirstSeen), parseXDRTime(chain.LastSeen)
		if firstSeen.IsZero() || lastSeen.IsZero() {
			continue
		}
		candidates = append(candidates, incidentlifecycle.Candidate{
			IncidentID: "inc-" + strings.TrimPrefix(chain.ID, "chain-"), SourceChainID: chain.ID,
			CorrelationKey: chain.CorrelationKey, Title: incidentTitleFromChain(row), Summary: chain.Summary,
			Severity: chain.Severity, FirstSeen: firstSeen, LastSeen: lastSeen, Evidence: evidence,
		})
	}
	snapshot, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, candidates)
	if err != nil {
		return err
	}
	if _, err := store.SyncActive(ctx, snapshot); err != nil {
		return fmt.Errorf("sync v2-active incidents: %w", err)
	}
	return nil
}

// syncTrafficIncidentCandidates materializes strong internal traffic
// detections even when the XDR graph has not produced a multi-stage
// hypothesis yet. A mirror sensor can see an internal exploit attempt while
// the victim has no runtime Agent, so waiting for a second telemetry source
// would hide the most important lateral movement evidence.
func syncTrafficIncidentCandidates(ctx context.Context, cfg *Config) error {
	if cfg == nil {
		return nil
	}
	return syncTrafficIncidentCandidatesWithStore(ctx, cfg, cfg.Incidents)
}

func syncTrafficIncidentCandidatesWithStore(ctx context.Context, cfg *Config, store *incidentlifecycle.PostgresStore) error {
	if cfg == nil || cfg.DBPool == nil || store == nil {
		return nil
	}
	rows, err := cfg.DBPool.Query(ctx, `
		SELECT event_uid, observed_at, raw_event::text
		FROM threat_events
		WHERE category = 'traffic' AND observed_at >= $1
		ORDER BY observed_at DESC
		LIMIT 100`, time.Now().Add(-30*time.Minute))
	if err != nil {
		return fmt.Errorf("query internal traffic candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]incidentlifecycle.Candidate, 0)
	seen := map[string]struct{}{}
	policy := loadXDRResponsePolicy(cfg)
	for rows.Next() {
		var eventUID, raw string
		var observedAt time.Time
		if err := rows.Scan(&eventUID, &observedAt, &raw); err != nil {
			continue
		}
		var event map[string]interface{}
		if json.Unmarshal([]byte(raw), &event) != nil || !xdrInternalLateralCandidate(event) {
			continue
		}
		if matchingXDRSuppression(policy.Suppressions,
			firstNonEmpty(validRuleID(xdrPickString(event, "component_rule_id")), validRuleID(xdrPickString(event, "rule_id"))),
			firstNonEmpty(xdrPickString(event, "rule_name"), xdrPickString(asMap(event["native_rule"]), "name")),
			xdrSourceIP(event), xdrVictimEntity(event), time.Now().UTC()) != nil {
			continue
		}
		if _, exists := seen[eventUID]; exists {
			continue
		}
		seen[eventUID] = struct{}{}
		victim := firstNonEmpty(xdrVictimIP(event), xdrVictimEntity(event), "目标资产")
		source := firstNonEmpty(xdrSourceIP(event), "未知来源")
		ruleName := firstNonEmpty(xdrPickString(event, "rule_name"), xdrPickString(event, "message"), "内网流量告警")
		title := victim + " 内网横向可疑流量"
		summary := fmt.Sprintf("%s · %s → %s", ruleName, source, victim)
		candidates = append(candidates, incidentlifecycle.Candidate{
			IncidentID:     "inc-traffic-" + safeID(eventUID),
			SourceChainID:  "chain-traffic-" + safeID(eventUID),
			CorrelationKey: "traffic:" + source + "->" + victim,
			Title:          title,
			Summary:        summary,
			Severity:       xdrPickString(event, "severity"),
			FirstSeen:      observedAt.UTC(),
			LastSeen:       observedAt.UTC(),
			Evidence: []incidentlifecycle.Evidence{{
				EventUID:      eventUID,
				SourceNodeUID: "traffic-node-" + eventUID,
				Stage:         firstNonEmpty(incidentStage(event), "lateral_movement"),
				ObservedAt:    observedAt.UTC(),
				Raw:           []byte(raw),
			}},
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate internal traffic candidates: %w", err)
	}
	if len(candidates) == 0 {
		return nil
	}
	snapshot, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, candidates)
	if err != nil {
		return fmt.Errorf("build traffic incident snapshot: %w", err)
	}
	if _, err := store.SyncActive(ctx, snapshot); err != nil {
		return fmt.Errorf("sync traffic incidents: %w", err)
	}
	return nil
}

// incidentPathHasStrongEdge prevents a weak same-source-IP edge from being
// promoted to an incident. Weak IP coincidence alone produces cross-asset
// false chains; a path must not contain any weak same-IP edge.
func incidentPathHasStrongEdge(path *models.PathEvidence) bool {
	if path == nil || len(path.Timeline) == 0 {
		return true
	}
	for _, step := range path.Timeline {
		edgeType := strings.ToLower(strings.TrimSpace(step.EdgeType))
		if edgeType == models.EdgeTypeWeakSameIP {
			return false
		}
	}
	return true
}

func loadLegacyIncidentStatus(id string) (incidentlifecycle.Status, bool) {
	value, exists := incidentStatusStore.Load(strings.TrimSpace(id))
	if !exists {
		return "", false
	}
	status := incidentlifecycle.Status(strings.TrimSpace(fmt.Sprint(value)))
	return status, status.Valid()
}

func incidentActor(ctx context.Context) incidentlifecycle.Actor {
	userID := auth.GetUserIDFromContext(ctx)
	if userID == 0 {
		return incidentlifecycle.Actor{Role: incidentlifecycle.Role(auth.GetRoleFromContext(ctx))}
	}
	return incidentlifecycle.Actor{
		ID:   fmt.Sprintf("user:%d", userID),
		Role: incidentlifecycle.Role(auth.GetRoleFromContext(ctx)),
	}
}

func incidentJSONRow(incident incidentlifecycle.Incident) map[string]interface{} {
	evidence := make([]map[string]interface{}, 0, len(incident.Evidence))
	evidenceValues := make([]interface{}, 0, len(incident.Evidence))
	stages := make([]string, 0, len(incident.Evidence))
	seenStages := map[string]struct{}{}
	sourceIPs := map[string]struct{}{}
	victimIPs := map[string]struct{}{}
	for _, item := range incident.Evidence {
		row := map[string]interface{}{
			"event_id": item.EventUID, "stage": item.Stage, "time": item.ObservedAt.Format(time.RFC3339Nano),
			"source_node_uid": item.SourceNodeUID, "raw": item.Raw,
		}
		var rawValue map[string]interface{}
		if json.Unmarshal(item.Raw, &rawValue) == nil {
			for _, key := range []string{"id", "event_type", "source_module", "source_engine", "src_ip", "dst_ip", "asset_id", "agent_id", "host_id", "summary", "raw_event", "raw_reference", "entity_id", "tactic", "technique"} {
				if value, exists := rawValue[key]; exists {
					row[key] = value
				}
			}
			if ip := xdrPickString(rawValue, "src_ip", "source_ip"); ip != "" {
				sourceIPs[ip] = struct{}{}
			}
			if ip := xdrPickString(rawValue, "dst_ip", "target_ip"); ip != "" {
				victimIPs[ip] = struct{}{}
			}
		}
		evidence = append(evidence, row)
		evidenceValues = append(evidenceValues, row)
		if _, exists := seenStages[item.Stage]; item.Stage != "" && !exists {
			seenStages[item.Stage] = struct{}{}
			stages = append(stages, item.Stage)
		}
	}
	sort.Strings(stages)
	return map[string]interface{}{
		"id": incident.ID, "source_chain_id": incident.SourceChainID, "algorithm": incident.Algorithm,
		"dedup_key": incident.DedupKey, "correlation": incident.CorrelationKey, "title": incident.Title,
		"summary": incident.Summary, "severity": incident.Severity, "severity_label": severityLabel(incident.Severity),
		"status": incident.Status, "status_label": incidentStatusLabel(string(incident.Status)), "assignee": incident.Assignee,
		"suppressed": incident.Suppressed, "suppressed_until": incident.SuppressedUntil, "suppression_reason": incident.SuppressionReason,
		"first_seen": incident.FirstSeen, "last_seen": incident.LastSeen, "created_at": incident.CreatedAt, "updated_at": incident.UpdatedAt,
		"acknowledge_due_at": incident.AcknowledgeDueAt, "resolve_due_at": incident.ResolveDueAt,
		"acknowledged_at": incident.AcknowledgedAt, "resolved_at": incident.ResolvedAt, "version": incident.Version,
		"event_count": len(evidence), "stages": stages, "stage_labels": stageLabels(stages), "events": evidence,
		"attack_chain": evidence, "stage_groups": incidentStageGroups(stages, evidenceValues), "source_ips": sortedKeys(sourceIPs),
		"victim_ips": sortedKeys(victimIPs), "audit": incident.Audit,
	}
}
