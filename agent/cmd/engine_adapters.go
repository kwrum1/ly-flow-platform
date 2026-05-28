package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type wazuhAlertInput struct {
	RuleID    string
	RuleName  string
	Level     int
	Decoder   string
	Location  string
	FullLog   string
	Timestamp time.Time
}

func componentAlertFromWazuh(input wazuhAlertInput, agent *Agent, raw contracts.RawReference) (contracts.ComponentAlert, error) {
	if input.Timestamp.IsZero() {
		input.Timestamp = time.Now().UTC()
	}
	raw.SourceEngine = contracts.SourceEngineWazuh
	raw.EventType = "alert"
	alert := contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion,
		ID:            stableAlertID("wazuh", input.RuleID, input.Location, input.FullLog),
		Category:      contracts.TelemetryHost,
		SourceEngine:  contracts.SourceEngineWazuh,
		RuleID:        input.RuleID,
		RuleName:      firstNonEmpty(input.RuleName, "Wazuh alert"),
		NativeRule: &contracts.RuleReference{Engine: contracts.SourceEngineWazuh, ID: input.RuleID, Category: input.Decoder, Source: "wazuh", Attributes: map[string]string{
			"decoder":  input.Decoder,
			"location": input.Location,
			"level":    fmt.Sprintf("%d", input.Level),
		}},
		Severity:      wazuhSeverity(input.Level),
		ScoreHint:     wazuhScore(input.Level),
		OccurredAt:    input.Timestamp,
		Source:        "wazuh",
		Entities:      contracts.EntityRef{AgentID: agentIDOrEmpty(agent), Hostname: hostnameOrEmpty(agent)},
		RawReference:  &raw,
		Summary:       firstNonEmpty(input.FullLog, input.RuleName, "Wazuh alert"),
		Details:       map[string]interface{}{"decoder": input.Decoder, "location": input.Location, "level": input.Level},
		Action:        string(contracts.ActionAudit),
		PolicyState:   contracts.PolicyAuditOnly,
		CandidateOnly: true,
	}
	return alert, alert.Validate()
}

type yaraMatchInput struct {
	Rule      string
	Namespace string
	Tags      []string
	FilePath  string
	FileHash  string
	MatchedAt time.Time
}

func componentAlertFromYARA(input yaraMatchInput, agent *Agent, raw contracts.RawReference) (contracts.ComponentAlert, error) {
	if input.MatchedAt.IsZero() {
		input.MatchedAt = time.Now().UTC()
	}
	raw.SourceEngine = contracts.SourceEngineYARA
	raw.EventType = "match"
	alert := contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion,
		ID:            stableAlertID("yara", input.Rule, input.FilePath, input.FileHash),
		Category:      contracts.TelemetryArtifact,
		SourceEngine:  contracts.SourceEngineYARA,
		RuleID:        input.Rule,
		RuleName:      input.Rule,
		NativeRule:    &contracts.RuleReference{Engine: contracts.SourceEngineYARA, ID: input.Rule, Category: input.Namespace, Source: "yara"},
		Severity:      contracts.SeverityHigh,
		ScoreHint:     75,
		OccurredAt:    input.MatchedAt,
		Source:        "yara",
		Entities:      contracts.EntityRef{AgentID: agentIDOrEmpty(agent), Hostname: hostnameOrEmpty(agent)},
		RawReference:  &raw,
		Summary:       fmt.Sprintf("YARA rule %s matched %s", input.Rule, input.FilePath),
		Details:       map[string]interface{}{"namespace": input.Namespace, "file_path": input.FilePath, "file_hash": input.FileHash},
		Tags:          input.Tags,
		Action:        string(contracts.ActionAudit),
		PolicyState:   contracts.PolicyAuditOnly,
		CandidateOnly: true,
	}
	return alert, alert.Validate()
}

type raspEventInput struct {
	RuleID      string
	RuleName    string
	HookType    string
	Language    string
	Runtime     string
	Application string
	Action      string
	Evidence    string
	OccurredAt  time.Time
}

func componentAlertFromRASP(input raspEventInput, agent *Agent, raw contracts.RawReference) (contracts.ComponentAlert, error) {
	if input.OccurredAt.IsZero() {
		input.OccurredAt = time.Now().UTC()
	}
	raw.SourceEngine = contracts.SourceEngineRASP
	raw.EventType = input.HookType
	action := firstNonEmpty(input.Action, string(contracts.ActionAudit))
	alert := contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion,
		ID:            stableAlertID("rasp", input.RuleID, input.Application, input.HookType, input.Evidence),
		Category:      contracts.TelemetryRASP,
		SourceEngine:  contracts.SourceEngineRASP,
		RuleID:        input.RuleID,
		RuleName:      firstNonEmpty(input.RuleName, input.HookType, "RASP event"),
		NativeRule:    &contracts.RuleReference{Engine: contracts.SourceEngineRASP, ID: input.RuleID, Category: input.HookType, Source: "rasp"},
		Severity:      contracts.SeverityHigh,
		ScoreHint:     80,
		OccurredAt:    input.OccurredAt,
		Source:        "rasp",
		Entities:      contracts.EntityRef{AgentID: agentIDOrEmpty(agent), Hostname: hostnameOrEmpty(agent), Application: input.Application},
		RawReference:  &raw,
		Summary:       firstNonEmpty(input.Evidence, input.RuleName, "RASP event"),
		Details:       map[string]interface{}{"hook_type": input.HookType, "language": input.Language, "runtime": input.Runtime, "application": input.Application},
		Action:        action,
		PolicyState:   contracts.PolicyAuditOnly,
		CandidateOnly: action != string(contracts.ActionBlock),
	}
	return alert, alert.Validate()
}

func wazuhSeverity(level int) contracts.AlertSeverity {
	switch {
	case level >= 12:
		return contracts.SeverityCritical
	case level >= 8:
		return contracts.SeverityHigh
	case level >= 4:
		return contracts.SeverityMedium
	default:
		return contracts.SeverityLow
	}
}

func wazuhScore(level int) int {
	switch {
	case level >= 12:
		return 90
	case level >= 8:
		return 75
	case level >= 4:
		return 55
	default:
		return 30
	}
}

func shortHash(value string) string {
	h := sha1.Sum([]byte(value))
	return hex.EncodeToString(h[:])[:16]
}
