package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

// trafficHit is one normalized internal traffic detection. It is deliberately
// small so the grouping logic can be unit-tested without a database.
type trafficHit struct {
	EventUID   string
	ObservedAt time.Time
	SrcIP      string
	DstIP      string
	Victim     string
	RuleID     string
	RuleName   string
	Severity   string
	Stage      string
	Raw        []byte
}

type trafficGroup struct {
	source    string
	ruleID    string
	ruleName  string
	severity  string
	victims   map[string]struct{}
	firstSeen time.Time
	lastSeen  time.Time
	evidence  []incidentlifecycle.Evidence
}

// lateralMinVictims is the minimum number of distinct victims needed for a low
// or medium severity internal hit to become an Incident. A single weak hit is
// kept in the event store as context, but does not open an Incident on its own.
// High/critical hits always open one. Set LYFLOW_LATERAL_MIN_VICTIMS=1 to
// restore the previous one-incident-per-victim behaviour.
func lateralMinVictims() int {
	raw := strings.TrimSpace(os.Getenv("LYFLOW_LATERAL_MIN_VICTIMS"))
	if raw == "" {
		return 2
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 2
	}
	return value
}

// buildTrafficIncidentCandidates groups internal traffic detections by root
// cause (source + rule) instead of creating one Incident per victim. This keeps
// a single noisy signature from producing hundreds of near-identical Incidents
// while preserving every event as evidence.
//
// It returns the candidates and the number of weak groups that were withheld.
func buildTrafficIncidentCandidates(hits []trafficHit, minVictims int) ([]incidentlifecycle.Candidate, int) {
	if minVictims < 1 {
		minVictims = 1
	}
	groups := make(map[string]*trafficGroup)
	order := make([]string, 0, len(hits))
	seen := make(map[string]struct{}, len(hits))

	for _, hit := range hits {
		if strings.TrimSpace(hit.EventUID) != "" {
			if _, exists := seen[hit.EventUID]; exists {
				continue
			}
			seen[hit.EventUID] = struct{}{}
		}
		source := firstNonEmpty(hit.SrcIP, "未知来源")
		ruleID := validRuleID(hit.RuleID)
		ruleName := firstNonEmpty(hit.RuleName, "内网流量告警")
		key := source + "|" + firstNonEmpty(ruleID, ruleName)

		group := groups[key]
		if group == nil {
			group = &trafficGroup{
				source:   source,
				ruleID:   ruleID,
				ruleName: ruleName,
				severity: hit.Severity,
				victims:  make(map[string]struct{}),
			}
			groups[key] = group
			order = append(order, key)
		}
		if victim := strings.TrimSpace(hit.Victim); victim != "" {
			group.victims[victim] = struct{}{}
		}
		if group.firstSeen.IsZero() || hit.ObservedAt.Before(group.firstSeen) {
			group.firstSeen = hit.ObservedAt.UTC()
		}
		if hit.ObservedAt.After(group.lastSeen) {
			group.lastSeen = hit.ObservedAt.UTC()
		}
		if severityRank(hit.Severity) > severityRank(group.severity) {
			group.severity = hit.Severity
		}
		group.evidence = append(group.evidence, incidentlifecycle.Evidence{
			EventUID:      hit.EventUID,
			SourceNodeUID: "traffic-node-" + hit.EventUID,
			Stage:         firstNonEmpty(hit.Stage, "lateral_movement"),
			ObservedAt:    hit.ObservedAt.UTC(),
			Raw:           hit.Raw,
		})
	}

	candidates := make([]incidentlifecycle.Candidate, 0, len(order))
	withheld := 0
	for _, key := range order {
		group := groups[key]
		if len(group.victims) < minVictims && severityRank(group.severity) < severityRank("high") {
			withheld++
			continue
		}
		victims := sortedVictims(group.victims)
		suffix := ""
		if len(victims) > 1 {
			suffix = fmt.Sprintf("（%d 个目标）", len(victims))
		}
		candidates = append(candidates, incidentlifecycle.Candidate{
			IncidentID:     "inc-traffic-" + safeID(key),
			SourceChainID:  "chain-traffic-" + safeID(key),
			CorrelationKey: "traffic:" + group.source + ":" + firstNonEmpty(group.ruleID, group.ruleName),
			Title:          group.source + " 内网横向可疑流量" + suffix,
			Summary: fmt.Sprintf("%s · %s → %s · %d 条证据",
				group.ruleName, group.source, victimPreview(victims, 3), len(group.evidence)),
			Severity:  group.severity,
			FirstSeen: group.firstSeen,
			LastSeen:  group.lastSeen,
			Evidence:  group.evidence,
		})
	}
	return candidates, withheld
}

func sortedVictims(set map[string]struct{}) []string {
	victims := make([]string, 0, len(set))
	for victim := range set {
		victims = append(victims, victim)
	}
	sort.Strings(victims)
	return victims
}

func victimPreview(victims []string, limit int) string {
	if len(victims) == 0 {
		return "目标资产"
	}
	if len(victims) <= limit {
		return strings.Join(victims, ", ")
	}
	return fmt.Sprintf("%s 等 %d 个", strings.Join(victims[:limit], ", "), len(victims))
}
