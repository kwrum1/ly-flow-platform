// Package lateral detects east-west movement patterns from normalized events.
// It is intentionally heuristic and evidence-oriented; the stage state machine
// remains the authority for incident progression.
package lateral

import (
	"sort"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type Config struct {
	Window      time.Duration
	MinTargets  int
	MinFailures int
}

func (config Config) withDefaults() Config {
	if config.Window <= 0 {
		config.Window = 10 * time.Minute
	}
	if config.MinTargets <= 0 {
		config.MinTargets = 3
	}
	if config.MinFailures <= 0 {
		config.MinFailures = 3
	}
	return config
}

type Finding struct {
	Type       string
	Source     string
	Targets    []string
	Techniques []string
	Score      float64
	FirstSeen  time.Time
	LastSeen   time.Time
	EventUIDs  []string
}

type observation struct {
	targets    map[string]time.Time
	techniques map[string]struct{}
	events     []string
	failures   int
	firstSeen  time.Time
	lastSeen   time.Time
}

var lateralPorts = map[int]string{
	445:  "T1021.002", // SMB
	3389: "T1021.001", // RDP
	5985: "T1021.006", // WinRM
	5986: "T1021.006",
	22:   "T1021.004", // SSH
}

func Detect(events []contracts.EventV2, config Config) []Finding {
	config = config.withDefaults()
	observations := map[string]*observation{}
	for _, event := range events {
		source := sourceKey(event)
		if source == "" {
			continue
		}
		current := observations[source]
		if current == nil {
			current = &observation{targets: map[string]time.Time{}, techniques: map[string]struct{}{}}
			observations[source] = current
		}
		at := event.Timestamps.EventAt
		if current.firstSeen.IsZero() || at.Before(current.firstSeen) {
			current.firstSeen = at
		}
		if current.lastSeen.IsZero() || at.After(current.lastSeen) {
			current.lastSeen = at
		}
		current.events = append(current.events, event.EventUID)
		if strings.EqualFold(string(event.Detection.Severity), "low") && strings.Contains(strings.ToLower(event.EventType), "auth") {
			current.failures++
		}
		if event.Entities.Network != nil {
			port := event.Entities.Network.DstPort
			if technique, ok := lateralPorts[port]; ok {
				target := strings.TrimSpace(event.Entities.Network.DstIP)
				if target != "" {
					current.targets[target] = at
					current.techniques[technique] = struct{}{}
				}
			}
		}
		for _, technique := range []string{event.Detection.TechniqueID} {
			if strings.HasPrefix(technique, "T1021") || technique == "T1110" || technique == "T1046" {
				current.techniques[technique] = struct{}{}
			}
		}
		if event.Detection.TechniqueID == "T1110" {
			current.failures++
		}
	}

	findings := make([]Finding, 0)
	for source, current := range observations {
		freshTargets := fresh(current.targets, current.lastSeen, config.Window)
		switch {
		case len(freshTargets) >= config.MinTargets:
			score := 0.4 + float64(len(freshTargets))/float64(config.MinTargets)*0.2
			if score > 1 {
				score = 1
			}
			findings = append(findings, Finding{
				Type: "lateral_movement", Source: source, Targets: freshTargets,
				Techniques: sortedKeys(current.techniques, "T1021"), Score: score,
				FirstSeen: current.firstSeen, LastSeen: current.lastSeen, EventUIDs: append([]string(nil), current.events...),
			})
		case current.failures >= config.MinFailures:
			findings = append(findings, Finding{
				Type: "credential_burst", Source: source, Targets: freshTargets,
				Techniques: sortedKeys(current.techniques, "T1110"), Score: 0.6,
				FirstSeen: current.firstSeen, LastSeen: current.lastSeen, EventUIDs: append([]string(nil), current.events...),
			})
		}
	}
	sort.Slice(findings, func(left, right int) bool {
		return findings[left].Score > findings[right].Score
	})
	return findings
}

func sourceKey(event contracts.EventV2) string {
	if event.Entities.Asset != nil && event.Entities.Asset.ID != "" {
		return event.Entities.Asset.ID
	}
	if event.Entities.Network != nil && event.Entities.Network.SrcIP != "" {
		return event.Entities.Network.SrcIP
	}
	return ""
}

func fresh(targets map[string]time.Time, now time.Time, window time.Duration) []string {
	result := make([]string, 0, len(targets))
	for target, at := range targets {
		if now.Sub(at) <= window {
			result = append(result, target)
		}
	}
	sort.Strings(result)
	return result
}

func sortedKeys(values map[string]struct{}, prefix string) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if strings.HasPrefix(value, prefix) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
