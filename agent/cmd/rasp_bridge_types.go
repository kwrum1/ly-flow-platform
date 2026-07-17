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
	decoder := json.NewDecoder(counter)
	decoder.DisallowUnknownFields()
	var request raspBridgeEventRequest
	if err := decoder.Decode(&request); err != nil {
		return raspBridgeEventRequest{}, counter.read, fmt.Errorf("decode RASP bridge event: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return raspBridgeEventRequest{}, counter.read, fmt.Errorf("decode RASP bridge event: %w", errRASPBridgeSchema)
		}
		return raspBridgeEventRequest{}, counter.read, fmt.Errorf("decode trailing RASP bridge data: %w", err)
	}
	return request, counter.read, nil
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
	if language != shared.LanguagePython && language != shared.LanguageJava {
		return false
	}
	for _, candidate := range allowed {
		if candidate == language {
			return true
		}
	}
	return false
}
