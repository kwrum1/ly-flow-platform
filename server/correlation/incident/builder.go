// Package incident turns correlated events into an incident-lifecycle candidate.
// It composes the stage state machine and entity graph; persistence and status
// transitions remain owned by server/incidentlifecycle.
package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/correlation/graph"
	"github.com/lyflow/ly-flow-platform/server/correlation/stage"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

var (
	ErrNoEvents = errors.New("incident builder: at least one event is required")
	ErrNoStage  = errors.New("incident builder: no mapped ATT&CK stage")
)

type Builder struct {
	Tenant string
	Config stage.Config
}

type Report struct {
	Candidate  incidentlifecycle.Candidate
	Stages     stage.Snapshot
	Components [][]string
	Techniques []string
}

func (builder Builder) Build(correlationKey, title string, events []contracts.EventV2) (Report, error) {
	if len(events) == 0 {
		return Report{}, ErrNoEvents
	}
	ordered := append([]contracts.EventV2(nil), events...)
	sort.SliceStable(ordered, func(left, right int) bool {
		return ordered[left].Timestamps.EventAt.Before(ordered[right].Timestamps.EventAt)
	})
	config := builder.Config
	if config.MaxJump <= 0 {
		// Real incidents legitimately skip stages; evidence/confidence gates still apply.
		config.MaxJump = 12
	}

	var state stage.State
	entityGraph := graph.New()
	evidence := make([]incidentlifecycle.Evidence, 0, len(ordered))
	techniques := map[string]struct{}{}
	severity := ""
	firstSeen := time.Time{}
	lastSeen := time.Time{}

	for _, event := range ordered {
		stageName := event.Detection.Stage
		if stageName == "" || stageName == contracts.StageUnknown {
			stageName = contracts.StageForTactic(event.Detection.TacticID)
		}
		if stageName == "" || stageName == contracts.StageUnknown {
			continue
		}
		confidence := event.Detection.Confidence
		if confidence <= 0 {
			confidence = 0.5
		}
		state.Apply(stage.Event{
			EventUID: event.EventUID, Source: string(event.Source), Stage: stageName,
			TechniqueID: event.Detection.TechniqueID, Confidence: confidence,
			EventAt: event.Timestamps.EventAt,
		}, config)
		entityGraph.AddEvent(event)

		if severityRank(string(event.Detection.Severity)) > severityRank(severity) {
			severity = string(event.Detection.Severity)
		}
		if event.Detection.TechniqueID != "" {
			techniques[event.Detection.TechniqueID] = struct{}{}
		}
		if firstSeen.IsZero() || event.Timestamps.EventAt.Before(firstSeen) {
			firstSeen = event.Timestamps.EventAt
		}
		if lastSeen.IsZero() || event.Timestamps.EventAt.After(lastSeen) {
			lastSeen = event.Timestamps.EventAt
		}
		sourceNode := ""
		if event.Entities.Asset != nil {
			sourceNode = event.Entities.Asset.ID
		}
		evidence = append(evidence, incidentlifecycle.Evidence{
			EventUID: event.EventUID, SourceNodeUID: sourceNode, Stage: string(stageName),
			ObservedAt: event.Timestamps.EventAt, Raw: append([]byte(nil), event.Payload...),
		})
	}

	snapshot := state.Snapshot()
	if snapshot.Current == "" || snapshot.Current == contracts.StageUnknown {
		return Report{}, ErrNoStage
	}
	if severity == "" {
		severity = string(contracts.SeverityLow)
	}
	tenant := strings.TrimSpace(builder.Tenant)
	if tenant == "" {
		tenant = "default"
	}
	correlationKey = strings.TrimSpace(correlationKey)
	if correlationKey == "" {
		correlationKey = ordered[0].CorrelationID
	}
	if correlationKey == "" {
		correlationKey = ordered[0].EventUID
	}
	if strings.TrimSpace(title) == "" {
		title = "关联攻击链"
	}
	candidate := incidentlifecycle.Candidate{
		IncidentID:     incidentID(correlationKey),
		SourceChainID:  correlationKey,
		CorrelationKey: correlationKey,
		Title:          title,
		Summary: fmt.Sprintf("阶段 %s，证据 %d 条，来源 %s",
			snapshot.Current, len(evidence), strings.Join(snapshot.Sources, ",")),
		Severity:  severity,
		FirstSeen: firstSeen,
		LastSeen:  lastSeen,
		Evidence:  evidence,
	}
	if _, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, []incidentlifecycle.Candidate{candidate}); err != nil {
		return Report{}, err
	}
	return Report{
		Candidate:  candidate,
		Stages:     snapshot,
		Components: entityGraph.Components(),
		Techniques: sortedKeys(techniques),
	}, nil
}

func incidentID(correlationKey string) string {
	digest := sha256.Sum256([]byte(correlationKey))
	return "inc-" + hex.EncodeToString(digest[:8])
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
