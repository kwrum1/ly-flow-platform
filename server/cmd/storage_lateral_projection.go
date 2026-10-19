package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/correlation/lateral"
)

func lateralDerivedEvents(events []contracts.EventV2) []contracts.EventV2 {
	if len(events) == 0 {
		return nil
	}
	tracker := lateral.NewTracker(lateral.Config{Window: 10 * time.Minute, MinTargets: 3})
	return lateralDerivedEventsFromFindings(events, tracker.Observe(events))
}

func lateralDerivedEventsFromFindings(events []contracts.EventV2, findings []lateral.Finding) []contracts.EventV2 {
	if len(findings) == 0 {
		return nil
	}
	byUID := make(map[string]contracts.EventV2, len(events))
	for _, event := range events {
		byUID[event.EventUID] = event
	}
	now := time.Now().UTC()
	derived := make([]contracts.EventV2, 0, len(findings))
	for _, finding := range findings {
		source, ok := sourceEventForFinding(byUID, finding)
		if !ok {
			continue
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"detector": "lyflow.lateral", "window_seconds": 600,
			"source": finding.Source, "targets": finding.Targets,
			"techniques": finding.Techniques, "score": finding.Score,
			"event_uids": finding.EventUIDs,
		})
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		event := source
		event.SchemaVersion = contracts.SecurityEventSchemaV2
		event.EventUID = "lateral-" + digest[:24]
		event.Source = contracts.SourceXDRV2
		event.EventType = "lateral.movement"
		event.Timestamps = contracts.EventTimestamps{EventAt: finding.LastSeen, ObservedAt: now, IngestedAt: now}
		event.Detection = contracts.Detection{
			RuleID:        "lyflow.lateral." + finding.Type,
			RuleVersion:   "1",
			RuleSource:    "lyflow-correlation",
			Severity:      contracts.SeverityHigh,
			Confidence:    clampConfidence(finding.Score),
			TacticID:      "TA0008",
			TechniqueID:   firstTechnique(finding.Techniques),
			Stage:         contracts.StageLateralMovement,
			Description:   "east-west movement across multiple targets",
			MappingSource: "lyflow.lateral.v1",
		}
		event.Payload = payload
		event.Raw = contracts.RawRef{
			NativeSchema: "lyflow.lateral.v1", NativeEventID: strings.Join(finding.EventUIDs, ","),
			Adapter: "lyflow.correlation.lateral", PayloadSHA256: digest,
		}
		if err := event.Validate(); err != nil {
			log.Printf("lateral derived event skipped: %v", err)
			continue
		}
		derived = append(derived, event)
	}
	return derived
}

func sourceEventForFinding(byUID map[string]contracts.EventV2, finding lateral.Finding) (contracts.EventV2, bool) {
	for _, uid := range finding.EventUIDs {
		if event, ok := byUID[uid]; ok {
			return event, true
		}
	}
	return contracts.EventV2{}, false
}

func firstTechnique(techniques []string) string {
	if len(techniques) == 0 {
		return "T1021"
	}
	return techniques[0]
}

func clampConfidence(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}
