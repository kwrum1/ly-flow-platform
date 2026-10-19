package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

const (
	raspBridgeEventSchemaVersion = "lyflow.rasp_bridge_event.v1"
	raspBridgeEventSQL           = "rasp.sql"
	raspBridgeEventCommand       = "rasp.command"
	raspBridgeEventFile          = "rasp.file"
	raspBridgeEventDeserialize   = "rasp.deserialization"
	raspBridgeEventHTTP          = "rasp.http"
	raspBridgeMaxBodyBytes       = 1 << 20
)

var (
	errRASPBridgeSchema  = errors.New("RASP bridge event schema invalid")
	errRASPBridgeBinding = errors.New("RASP bridge event binding invalid")
)

type raspBridgeEventRequest struct {
	SchemaVersion string                  `json:"schema_version"`
	EventID       string                  `json:"event_id"`
	AgentID       string                  `json:"agent_id"`
	PolicyID      string                  `json:"policy_id"`
	PolicyVersion uint64                  `json:"policy_version"`
	Language      shared.Language         `json:"language"`
	EventType     string                  `json:"event_type"`
	Severity      contracts.AlertSeverity `json:"severity"`
	ObservedAt    time.Time               `json:"observed_at"`
	Application   string                  `json:"application"`
	RuleID        string                  `json:"rule_id"`
	Evidence      string                  `json:"evidence"`
	TraceID       string                  `json:"trace_id,omitempty"`
}

type raspBridgePolicyBinding struct {
	AgentID      string
	PolicyID     string
	Version      uint64
	Mode         shared.Mode
	ExpiresAt    time.Time
	Languages    []shared.Language
	Signature    string
	Acknowledged bool
}

type raspBridgeDeliveryItem struct {
	request   raspBridgeEventRequest
	telemetry contracts.TelemetryEnvelope
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(destination []byte) (int, error) {
	count, err := reader.reader.Read(destination)
	reader.read += count
	return count, err
}

func decodeRASPBridgeEvent(w http.ResponseWriter, r *http.Request, maxBytes int64) (raspBridgeEventRequest, int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	counter := &countingReader{reader: r.Body}
	raw, err := io.ReadAll(counter)
	if err != nil {
		return raspBridgeEventRequest{}, counter.read, fmt.Errorf("read RASP bridge event: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var request raspBridgeEventRequest
	if err := decoder.Decode(&request); err == nil {
		var trailing json.RawMessage
		if trailingErr := decoder.Decode(&trailing); errors.Is(trailingErr, io.EOF) {
			return request, counter.read, nil
		}
	}
	var legacy map[string]interface{}
	if err := json.Unmarshal(raw, &legacy); err != nil || !looksLikeLegacyRASPEvent(legacy) {
		return raspBridgeEventRequest{}, counter.read, fmt.Errorf("decode RASP bridge event: %w", errRASPBridgeSchema)
	}
	return normalizeLegacyRASPEvent(legacy, time.Now().UTC()), counter.read, nil
}

func looksLikeLegacyRASPEvent(event map[string]interface{}) bool {
	if event == nil {
		return false
	}
	if value, ok := event["schema_version"].(string); ok && strings.TrimSpace(value) != "" {
		return false
	}
	if value, ok := event["language"].(string); ok && strings.TrimSpace(value) != "" {
		return true
	}
	if _, ok := event["hook_type"]; ok {
		return true
	}
	if value, ok := event["event_type"].(string); ok && strings.HasPrefix(strings.ToLower(value), "rasp.") {
		return true
	}
	return false
}

func normalizeLegacyRASPEvent(event map[string]interface{}, now time.Time) raspBridgeEventRequest {
	language := legacyLanguage(legacyString(event, "language", "runtime"))
	eventType := legacyEventType(legacyString(event, "event_type", "hook_type", "type"))
	evidence := legacyString(event, "command", "cmdline", "query", "sql", "path", "file", "url", "payload", "message", "summary")
	if evidence == "" {
		evidence = "legacy RASP probe event"
	}
	severity := contracts.AlertSeverity(strings.ToLower(legacyString(event, "severity")))
	switch severity {
	case contracts.SeverityLow, contracts.SeverityMedium, contracts.SeverityHigh, contracts.SeverityCritical:
	default:
		severity = contracts.SeverityMedium
	}
	observed := now
	if value := legacyString(event, "observed_at", "occurred_at", "timestamp"); value != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
			observed = parsed.UTC()
		}
	}
	application := legacyString(event, "application", "app", "process")
	if application == "" {
		application = "legacy-" + string(language) + "-app"
	}
	ruleID := legacyString(event, "rule_id", "hook_type", "event_type")
	if ruleID == "" {
		ruleID = string(eventType)
	}
	return raspBridgeEventRequest{
		SchemaVersion: raspBridgeEventSchemaVersion,
		EventID:       fmt.Sprintf("legacy-%d", now.UnixNano()),
		Language:      language,
		EventType:     eventType,
		Severity:      severity,
		ObservedAt:    observed,
		Application:   application,
		RuleID:        ruleID,
		Evidence:      evidence,
		TraceID:       legacyString(event, "trace_id", "trace"),
	}
}

func legacyLanguage(value string) shared.Language {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "python", "py":
		return shared.LanguagePython
	case "java", "jvm":
		return shared.LanguageJava
	case "php":
		return shared.LanguagePHP
	case "node", "nodejs", "javascript", "js":
		return shared.LanguageNodeJS
	case "dotnet", ".net", "csharp", "c#":
		return shared.LanguageDotnet
	case "go", "golang":
		return shared.LanguageGo
	default:
		return shared.LanguagePython
	}
}

func legacyEventType(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "sql"):
		return raspBridgeEventSQL
	case strings.Contains(lower, "command"), strings.Contains(lower, "exec"), strings.Contains(lower, "process"):
		return raspBridgeEventCommand
	case strings.Contains(lower, "file"), strings.Contains(lower, "path"):
		return raspBridgeEventFile
	case strings.Contains(lower, "deserial"):
		return raspBridgeEventDeserialize
	case strings.Contains(lower, "ssrf"), strings.Contains(lower, "http"), strings.Contains(lower, "url"):
		return raspBridgeEventHTTP
	default:
		return raspBridgeEventCommand
	}
}

func legacyString(event map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := event[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed)
			}
		case json.Number:
			return typed.String()
		case float64:
			return fmt.Sprintf("%g", typed)
		}
	}
	return ""
}

func (request raspBridgeEventRequest) validate(binding raspBridgePolicyBinding) error {
	if request.SchemaVersion != raspBridgeEventSchemaVersion || !knownRASPBridgeEventType(request.EventType) || !knownRASPBridgeSeverity(request.Severity) {
		return errRASPBridgeSchema
	}
	if strings.TrimSpace(request.EventID) == "" || len(request.EventID) > 128 || strings.TrimSpace(request.Application) == "" || strings.TrimSpace(request.RuleID) == "" || strings.TrimSpace(request.Evidence) == "" || request.ObservedAt.IsZero() {
		return errRASPBridgeSchema
	}
	if len(request.Application) > 256 || len(request.RuleID) > 256 || len(request.Evidence) > 64*1024 || len(request.TraceID) > 256 {
		return errRASPBridgeSchema
	}
	if !binding.Acknowledged || binding.Mode != shared.ModeMonitor || request.AgentID != binding.AgentID || request.PolicyID != binding.PolicyID || request.PolicyVersion != binding.Version {
		return errRASPBridgeBinding
	}
	if !raspBridgeLanguageAllowed(request.Language, binding.Languages) {
		return errRASPBridgeBinding
	}
	return nil
}

func (request raspBridgeEventRequest) delivery(binding raspBridgePolicyBinding, receivedAt time.Time) (raspBridgeDeliveryItem, error) {
	fields := map[string]interface{}{
		"severity": request.Severity, "language": request.Language, "application": request.Application,
		"rule_id": request.RuleID, "evidence": request.Evidence, "policy_id": request.PolicyID,
		"policy_version": request.PolicyVersion, "policy_signature": binding.Signature,
	}
	switch request.EventType {
	case raspBridgeEventCommand:
		fields["command"] = request.Evidence
	case raspBridgeEventSQL:
		fields["query"] = request.Evidence
	case raspBridgeEventFile:
		fields["path"] = request.Evidence
	case raspBridgeEventDeserialize:
		fields["payload"] = request.Evidence
	case raspBridgeEventHTTP:
		fields["url"] = request.Evidence
	}
	telemetry := contracts.TelemetryEnvelope{
		SchemaVersion: contracts.TelemetrySchemaVersion,
		ID:            "rasp-" + request.EventID,
		Category:      contracts.TelemetryRASP,
		EventType:     request.EventType,
		ObservedAt:    request.ObservedAt.UTC(),
		ReceivedAt:    receivedAt.UTC(),
		Source:        "rasp-" + string(request.Language),
		SourceEngine:  contracts.SourceEngineRASP,
		RulePack:      fmt.Sprintf("%s@%d", request.PolicyID, request.PolicyVersion),
		Entities: contracts.EntityRef{
			AgentID: request.AgentID, Application: request.Application, TraceID: request.TraceID,
		},
		Fields:  fields,
		Excerpt: truncateForMetadata(request.Evidence, 280),
	}
	if err := telemetry.Validate(); err != nil {
		return raspBridgeDeliveryItem{}, fmt.Errorf("validate RASP telemetry: %w", err)
	}
	canonical, err := telemetry.Canonical(contracts.PrincipalIdentity(binding.AgentID), receivedAt.UTC())
	if err != nil {
		return raspBridgeDeliveryItem{}, fmt.Errorf("canonicalize RASP telemetry: %w", err)
	}
	if err := canonical.Validate(); err != nil {
		return raspBridgeDeliveryItem{}, fmt.Errorf("validate canonical RASP event: %w", err)
	}
	return raspBridgeDeliveryItem{request: request, telemetry: telemetry}, nil
}

func knownRASPBridgeEventType(eventType string) bool {
	switch eventType {
	case raspBridgeEventSQL, raspBridgeEventCommand, raspBridgeEventFile, raspBridgeEventDeserialize, raspBridgeEventHTTP:
		return true
	default:
		return false
	}
}

func knownRASPBridgeSeverity(severity contracts.AlertSeverity) bool {
	switch severity {
	case contracts.SeverityLow, contracts.SeverityMedium, contracts.SeverityHigh, contracts.SeverityCritical:
		return true
	default:
		return false
	}
}

func raspBridgeLanguageAllowed(language shared.Language, allowed []shared.Language) bool {
	switch language {
	case shared.LanguagePython, shared.LanguageJava, shared.LanguagePHP,
		shared.LanguageNodeJS, shared.LanguageDotnet, shared.LanguageGo:
	default:
		return false
	}
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == language {
			return true
		}
	}
	return false
}
