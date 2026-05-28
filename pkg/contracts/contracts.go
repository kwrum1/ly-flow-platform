package contracts

import "time"

const (
	TelemetrySchemaVersion      = "lyflow.telemetry.v1"
	ComponentAlertSchemaVersion = "lyflow.component_alert.v1"
)

type TelemetryCategory string

const (
	TelemetryTraffic  TelemetryCategory = "traffic"
	TelemetryNetwork  TelemetryCategory = "network"
	TelemetryHost     TelemetryCategory = "host"
	TelemetryRuntime  TelemetryCategory = "runtime"
	TelemetryLog      TelemetryCategory = "log"
	TelemetryRASP     TelemetryCategory = "rasp"
	TelemetryArtifact TelemetryCategory = "artifact"
	TelemetryLogAudit TelemetryCategory = "log_audit"
)

type SourceEngine string

const (
	SourceEngineLyFlow    SourceEngine = "lyflow"
	SourceEngineSuricata  SourceEngine = "suricata"
	SourceEngineWazuh     SourceEngine = "wazuh"
	SourceEngineSigma     SourceEngine = "sigma"
	SourceEngineYARA      SourceEngine = "yara"
	SourceEngineRASP      SourceEngine = "rasp"
	SourceEngineAgent     SourceEngine = "agent"
	SourceEngineRuntime   SourceEngine = "runtime"
	SourceEngineLogAudit  SourceEngine = "log_audit"
	SourceEngineDPIEngine SourceEngine = "dpi_engine"
)

type AlertAction string

const (
	ActionAudit AlertAction = "audit"
	ActionBlock AlertAction = "block"
	ActionAllow AlertAction = "allow"
)

type PolicyState string

const (
	PolicyAuditOnly   PolicyState = "audit_only"
	PolicyCanaryBlock PolicyState = "canary_block"
	PolicyBlock       PolicyState = "block"
)

type RuleReference struct {
	Engine     SourceEngine      `json:"engine,omitempty"`
	ID         string            `json:"id,omitempty"`
	Name       string            `json:"name,omitempty"`
	Version    string            `json:"version,omitempty"`
	Revision   string            `json:"revision,omitempty"`
	Category   string            `json:"category,omitempty"`
	Source     string            `json:"source,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type EntityRef struct {
	AgentID     string `json:"agent_id,omitempty"`
	HostID      string `json:"host_id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	User        string `json:"user,omitempty"`
	ProcessID   string `json:"process_id,omitempty"`
	Application string `json:"application,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	TargetIP    string `json:"target_ip,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
}

type RawReference struct {
	Stream       string       `json:"stream,omitempty"`
	MessageID    string       `json:"message_id,omitempty"`
	Path         string       `json:"path,omitempty"`
	Offset       int64        `json:"offset,omitempty"`
	Hash         string       `json:"hash,omitempty"`
	SourceEngine SourceEngine `json:"source_engine,omitempty"`
	EventType    string       `json:"event_type,omitempty"`
}

type TelemetryEnvelope struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Category      TelemetryCategory `json:"category"`
	EventType     string            `json:"event_type"`
	ObservedAt    time.Time         `json:"observed_at"`
	ReceivedAt    time.Time         `json:"received_at,omitempty"`
	Source        string            `json:"source"`
	SourceEngine  SourceEngine      `json:"source_engine,omitempty"`
	EngineVersion string            `json:"engine_version,omitempty"`
	RulePack      string            `json:"rule_pack,omitempty"`
	Entities      EntityRef         `json:"entities"`
	RawReference  *RawReference     `json:"raw_reference,omitempty"`
	Fields        map[string]any    `json:"fields,omitempty"`
	Excerpt       string            `json:"excerpt,omitempty"`
	Labels        []string          `json:"labels,omitempty"`
}

type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

type ComponentAlert struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Category      TelemetryCategory `json:"category"`
	SourceEngine  SourceEngine      `json:"source_engine,omitempty"`
	RuleID        string            `json:"rule_id"`
	RuleName      string            `json:"rule_name"`
	NativeRule    *RuleReference    `json:"native_rule,omitempty"`
	Severity      AlertSeverity     `json:"severity"`
	ScoreHint     int               `json:"score_hint"`
	StageHint     string            `json:"stage_hint,omitempty"`
	Confidence    float64           `json:"confidence,omitempty"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Source        string            `json:"source"`
	EngineVersion string            `json:"engine_version,omitempty"`
	RulePack      string            `json:"rule_pack,omitempty"`
	Entities      EntityRef         `json:"entities"`
	RawReference  *RawReference     `json:"raw_reference,omitempty"`
	EvidenceRefs  []RawReference    `json:"evidence_refs,omitempty"`
	Summary       string            `json:"summary"`
	Details       map[string]any    `json:"details,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Action        string            `json:"action,omitempty"`
	PolicyState   PolicyState       `json:"policy_state,omitempty"`
	CandidateOnly bool              `json:"candidate_only"`
}

func IsKnownTelemetryCategory(category TelemetryCategory) bool {
	switch category {
	case TelemetryTraffic, TelemetryNetwork, TelemetryHost, TelemetryRuntime, TelemetryLog, TelemetryRASP, TelemetryArtifact, TelemetryLogAudit:
		return true
	default:
		return false
	}
}

func IsKnownSourceEngine(engine SourceEngine) bool {
	switch engine {
	case "", SourceEngineLyFlow, SourceEngineSuricata, SourceEngineWazuh, SourceEngineSigma, SourceEngineYARA, SourceEngineRASP, SourceEngineAgent, SourceEngineRuntime, SourceEngineLogAudit, SourceEngineDPIEngine:
		return true
	default:
		return false
	}
}

func (e TelemetryEnvelope) Validate() error {
	if e.SchemaVersion != TelemetrySchemaVersion {
		return ValidationError("invalid telemetry schema_version")
	}
	if e.ID == "" || e.Category == "" || e.EventType == "" || e.Source == "" || e.ObservedAt.IsZero() {
		return ValidationError("missing required telemetry field")
	}
	if !IsKnownTelemetryCategory(e.Category) {
		return ValidationError("unknown telemetry category")
	}
	if !IsKnownSourceEngine(e.SourceEngine) {
		return ValidationError("unknown telemetry source_engine")
	}
	return nil
}

func (a ComponentAlert) Validate() error {
	if a.SchemaVersion != ComponentAlertSchemaVersion {
		return ValidationError("invalid component alert schema_version")
	}
	if a.ID == "" || a.Category == "" || a.RuleID == "" || a.RuleName == "" || a.Severity == "" || a.Source == "" || a.Summary == "" || a.OccurredAt.IsZero() {
		return ValidationError("missing required component alert field")
	}
	if a.ScoreHint < 0 || a.ScoreHint > 100 {
		return ValidationError("score_hint out of range")
	}
	if !IsKnownTelemetryCategory(a.Category) {
		return ValidationError("unknown component alert category")
	}
	if !IsKnownSourceEngine(a.SourceEngine) {
		return ValidationError("unknown component alert source_engine")
	}
	return nil
}

type ValidationError string

func (e ValidationError) Error() string { return string(e) }
