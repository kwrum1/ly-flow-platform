package engine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type Bundle struct {
	Version string
	Digest  string
	Rules   []RuntimeRule
}

func EmptyBundle() *Bundle { return &Bundle{Version: "empty", Rules: nil} }

func NewBundle(version string, rules []RuntimeRule) (*Bundle, error) {
	for i := range rules {
		if rules[i].Regex {
			re, err := regexp.Compile(rules[i].Value)
			if err != nil {
				return nil, err
			}
			rules[i].compiled = re
		}
		for j := range rules[i].Conditions {
			condition := &rules[i].Conditions[j]
			if condition.Regex || strings.EqualFold(strings.TrimSpace(condition.Operator), "regex") {
				re, err := regexp.Compile(condition.Value)
				if err != nil {
					return nil, err
				}
				condition.compiled = re
			}
		}
	}
	return &Bundle{Version: version, Rules: rules}, nil
}

func (b *Bundle) Match(env contracts.TelemetryEnvelope) []contracts.ComponentAlert {
	if b == nil {
		return nil
	}
	if isRASPHealthEvent(env) {
		return nil
	}
	out := make([]contracts.ComponentAlert, 0)
	for _, rule := range b.Rules {
		if rule.Category != env.Category {
			continue
		}
		// A regex that matches the empty string is not a detector: it would
		// fire on every event. Broken upstream conversions have produced
		// "(?i)" patterns, so reject them at runtime instead of flooding.
		if rule.Regex && rule.compiled != nil && rule.compiled.MatchString("") {
			continue
		}
		if !rule.matches(env) {
			continue
		}
		alert := contracts.ComponentAlert{SchemaVersion: contracts.ComponentAlertSchemaVersion, Category: rule.Category, RuleID: rule.ID, RuleName: rule.Name, Severity: rule.Severity, ScoreHint: rule.ScoreHint, StageHint: rule.StageHint, Confidence: 0.8, Summary: rule.Name, CandidateOnly: rule.Candidate}
		// Preserve the telemetry fields on the alert. RASP enforcement state
		// (blocked / would_block / policy_version) lives there and must survive
		// the rule match, otherwise the console can never prove a block.
		if len(env.Fields) > 0 {
			details := make(map[string]any, len(env.Fields))
			for key, value := range env.Fields {
				details[key] = value
			}
			alert.Details = details
		}
		action, _ := env.Fields["action"].(string)
		blocked, _ := env.Fields["blocked"].(bool)
		if action == "block" || blocked {
			alert.Action = string(contracts.ActionBlock)
			alert.PolicyState = contracts.PolicyBlock
		}
		if applyTrafficNoisePolicy(&alert) {
			continue
		}
		out = append(out, alert)
	}
	// One RASP probe event is one attack. Matching several rules (native
	// detector + generic OWASP signatures) must not create several alerts, or
	// the overview multiplies one hit into a fake flood.
	if env.Category == contracts.TelemetryRASP && len(out) > 1 {
		best := out[0]
		for _, candidate := range out[1:] {
			if betterRASPAlert(candidate, best) {
				best = candidate
			}
		}
		out = []contracts.ComponentAlert{best}
	}
	return out
}

func isRASPHealthEvent(env contracts.TelemetryEnvelope) bool {
	if env.Category != contracts.TelemetryRASP {
		return false
	}
	eventType := strings.ToLower(strings.TrimSpace(env.EventType))
	return strings.Contains(eventType, "heartbeat") || strings.Contains(eventType, "control.health")
}

func betterRASPAlert(candidate, current contracts.ComponentAlert) bool {
	if candidate.ScoreHint != current.ScoreHint {
		return candidate.ScoreHint > current.ScoreHint
	}
	candidateNative := strings.HasPrefix(strings.ToLower(candidate.RuleID), "rasp-")
	currentNative := strings.HasPrefix(strings.ToLower(current.RuleID), "rasp-")
	if candidateNative != currentNative {
		return candidateNative
	}
	return candidate.RuleID < current.RuleID
}

func applyTrafficNoisePolicy(alert *contracts.ComponentAlert) bool {
	if alert == nil || alert.Category != contracts.TelemetryTraffic {
		return false
	}
	id := strings.ToLower(strings.TrimSpace(alert.RuleID))
	name := strings.ToLower(strings.TrimSpace(alert.RuleName))
	if strings.HasPrefix(name, "suricata traffic-id:") {
		return true
	}
	matches := func(ids []string, names []string) bool {
		for _, candidate := range ids {
			if id == strings.ToLower(candidate) {
				return true
			}
		}
		for _, candidate := range names {
			if strings.Contains(name, strings.ToLower(candidate)) {
				return true
			}
		}
		return false
	}
	if matches(
		[]string{
			"oisf-trafficid-300000001",
			"snort-community-27085",
			"snort-community-3135",
			"snort-community-23725", "snort-community-32888",
			"snort-community-28428", "snort-community-28429", "snort-community-28430",
			"snort-community-32038", "snort-community-32039", "snort-community-32043", "snort-community-32069",
			"snort-community-46435", "snort-community-46436", "snort-community-46438",
			"snort-community-25949", "snort-community-46785", "snort-community-46786", "snort-community-48764", "snort-community-48765", "snort-community-48766", "snort-community-48767", "snort-community-48844", "snort-community-48904", "snort-community-49396", "snort-community-49397", "snort-community-49398",
			"oisf-trafficid-300000010", "oisf-trafficid-300000011", "oisf-trafficid-300000012", "oisf-trafficid-300000013", "oisf-trafficid-300000014", "oisf-trafficid-300000015",
			"et-open-1000001", "et-open-1000050", "suricata-etopen-1000050",
		},
		[]string{
			"SURICATA TRAFFIC-ID: Ubuntu APT-GET",
			"EXPLOIT-KIT Unknown Malvertising exploit kit Hostile Jar pipe.class",
			"FILE-IDENTIFY PNG file download request",
			"MALWARE-CNC Win.Backdoor.Chopper web shell connection",
			"NETBIOS SMB Trans2 QUERY_FILE_INFO attempt",
			"FILE-IDENTIFY Portable Executable binary file magic detected",
			"INDICATOR-COMPROMISE Potential Redirect from Compromised WordPress site to Fedex",
			"SURICATA TRAFFIC-ID: google",
			"ET TROJAN High DNS Query Count Possible Tunnel", "ET TROJAN Possible DNS Tunnel",
			"OS-OTHER Bash environment variable injection attempt",
			"EXPLOIT-KIT Glazunov exploit kit",
			"MALWARE-CNC Vbs.Downloader", "MALWARE-CNC Win.Trojan.Zebrocy", "MALWARE-CNC Win.Downloader.Zebrocy",
		}) {
		return true
	}
	return false
}

func (b *Bundle) Counts() map[string]int {
	counts := map[string]int{"traffic": 0, "runtime": 0, "rasp": 0, "log_audit": 0}
	if b == nil {
		return counts
	}
	for _, rule := range b.Rules {
		counts[string(rule.Category)]++
	}
	return counts
}

func (r RuntimeRule) matches(env contracts.TelemetryEnvelope) bool {
	if len(r.Conditions) > 0 {
		for _, condition := range r.Conditions {
			if !condition.matches(env) {
				return false
			}
		}
		return true
	}
	condition := MatchCondition{Field: r.Field, Operator: r.Operator, Value: r.Value, Regex: r.Regex, compiled: r.compiled}
	return condition.matches(env)
}

func (c MatchCondition) matches(env contracts.TelemetryEnvelope) bool {
	value := fieldValue(env, c.Field)
	operator := strings.ToLower(strings.TrimSpace(c.Operator))
	if operator == "" {
		if c.Regex {
			operator = "regex"
		} else {
			operator = "contains"
		}
	}
	switch operator {
	case "equals", "eq", "==":
		return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(c.Value))
	case "not_equals", "neq", "!=":
		return !strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(c.Value))
	case "prefix", "starts_with":
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(c.Value))
	case "suffix", "ends_with":
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(c.Value))
	case "exists":
		return strings.TrimSpace(value) != ""
	case "not_exists":
		return strings.TrimSpace(value) == ""
	case "regex":
		if c.compiled == nil {
			return false
		}
		return c.compiled.MatchString(value)
	}
	if c.Regex && c.compiled != nil {
		return c.compiled.MatchString(value)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(c.Value))
}

func fieldValue(env contracts.TelemetryEnvelope, field string) string {
	field = strings.TrimSpace(field)
	switch field {
	case "event_type", "type":
		return env.EventType
	case "excerpt", "message", "raw":
		return firstNonEmpty(env.Excerpt, mapFieldValue(env.Fields, field))
	case "source", "collector":
		return firstNonEmpty(mapFieldValue(env.Fields, field), env.Source)
	case "source_ip", "src_ip", "entities.source_ip":
		return env.Entities.SourceIP
	case "target_ip", "dst_ip", "entities.target_ip":
		return env.Entities.TargetIP
	case "agent_id", "entities.agent_id":
		return env.Entities.AgentID
	case "hostname", "host", "entities.hostname":
		return env.Entities.Hostname
	case "user", "username", "entities.user":
		return env.Entities.User
	default:
		return mapFieldValue(env.Fields, field)
	}
}

func mapFieldValue(fields map[string]interface{}, field string) string {
	if fields == nil {
		return ""
	}
	if v, ok := fields[field]; ok && v != nil {
		return strings.TrimSpace(toString(v))
	}
	if strings.Contains(field, ".") {
		var cur interface{} = fields
		for _, part := range strings.Split(field, ".") {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return ""
			}
			cur = m[part]
		}
		if cur != nil {
			return strings.TrimSpace(toString(cur))
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return fmt.Sprint(x)
	}
}
