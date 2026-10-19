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
	return syncActiveIncidentStore(ctx, cfg.Incidents, input)
}

func syncActiveIncidentStore(ctx context.Context, store *incidentlifecycle.PostgresStore, input xdrIncidentInput) error {
	candidates := make([]incidentlifecycle.Candidate, 0)
	for _, chain := range input.incidentChains() {
		if chain.EventCount < 2 || len(uniqueStrings(chain.Stages)) < 2 || chain.CandidateOnly && chain.PathEvidence == nil {
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
