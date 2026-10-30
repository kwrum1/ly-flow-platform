package contracts

import (
	"fmt"
	"strings"
)

// Network field quality flags. They document *why* a field is absent instead
// of silently writing a zero value. `insufficient_telemetry` marks an event
// that must not be used to trigger rules requiring the missing field.
const (
	QualityMissingSrcIP          QualityFlag = "missing_src_ip"
	QualityMissingDstIP          QualityFlag = "missing_dst_ip"
	QualityMissingSrcPort        QualityFlag = "missing_src_port"
	QualityMissingDstPort        QualityFlag = "missing_dst_port"
	QualityMissingProtocol       QualityFlag = "missing_proto"
	QualityInsufficientTelemetry QualityFlag = "insufficient_telemetry"
)

// FieldValidationMode controls how strictly network field completeness is
// enforced. New validation must start in shadow mode (the plan's Gate 1).
type FieldValidationMode string

const (
	FieldValidationOff     FieldValidationMode = "off"
	FieldValidationShadow  FieldValidationMode = "shadow"
	FieldValidationEnforce FieldValidationMode = "enforce"
)

// ParseFieldValidationMode maps configuration text onto a mode. Unknown values
// fall back to shadow so a typo never silently disables the check.
func ParseFieldValidationMode(raw string) FieldValidationMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "enforce", "strict", "on":
		return FieldValidationEnforce
	case "off", "disabled", "none":
		return FieldValidationOff
	case "shadow", "":
		return FieldValidationShadow
	default:
		return FieldValidationShadow
	}
}

// NetworkFieldIssue is one missing or invalid network field with a reason.
type NetworkFieldIssue struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// NetworkFieldReport is the result of inspecting an event's network entity.
type NetworkFieldReport struct {
	IsNetwork      bool                `json:"is_network"`
	Complete       bool                `json:"complete"`
	Issues         []NetworkFieldIssue `json:"issues,omitempty"`
	SuggestedFlags []QualityFlag       `json:"suggested_flags,omitempty"`
}

// String renders a compact diagnostic for logs.
func (report NetworkFieldReport) String() string {
	if !report.IsNetwork {
		return "not-network"
	}
	if report.Complete {
		return "complete"
	}
	parts := make([]string, 0, len(report.Issues))
	for _, issue := range report.Issues {
		parts = append(parts, issue.Field+":"+issue.Reason)
	}
	return strings.Join(parts, ",")
}

// IsNetworkEvent decides whether the five-tuple requirement applies.
func (event EventV2) IsNetworkEvent() bool {
	if event.Entities.Network != nil {
		return true
	}
	switch event.Source {
	case SourceSuricata, SourceDPIEngine, SourceAgentTraffic:
		return true
	}
	for _, prefix := range []string{
		"network.", "traffic.", "flow.", "session.", "dns.", "http.", "tls.",
	} {
		if strings.HasPrefix(event.EventType, prefix) {
			return true
		}
	}
	return false
}

func knownPort(port int) bool {
	return port > 0 && port <= 65535
}

// NetworkFieldReport inspects the event without mutating it. A port of 0 is
// treated as unknown: the legacy pipeline used 0 as a "missing" sentinel and
// writing it back as a real port would be a false observation.
func (event EventV2) NetworkFieldReport() NetworkFieldReport {
	report := NetworkFieldReport{IsNetwork: event.IsNetworkEvent()}
	if !report.IsNetwork {
		report.Complete = true
		return report
	}

	network := event.Entities.Network
	if network == nil {
		report.Issues = append(report.Issues, NetworkFieldIssue{Field: "entities.network", Reason: "missing"})
		report.SuggestedFlags = append(report.SuggestedFlags, QualityInsufficientTelemetry)
		return report
	}

	add := func(field, reason string, flag QualityFlag) {
		report.Issues = append(report.Issues, NetworkFieldIssue{Field: field, Reason: reason})
		report.SuggestedFlags = append(report.SuggestedFlags, flag)
	}

	if strings.TrimSpace(network.SrcIP) == "" {
		add("network.src_ip", "missing", QualityMissingSrcIP)
	}
	if strings.TrimSpace(network.DstIP) == "" {
		add("network.dst_ip", "missing", QualityMissingDstIP)
	}
	if network.SrcPort == 0 {
		add("network.src_port", "missing", QualityMissingSrcPort)
	} else if !knownPort(network.SrcPort) {
		add("network.src_port", "out_of_range", QualityMissingSrcPort)
	}
	if network.DstPort == 0 {
		add("network.dst_port", "missing", QualityMissingDstPort)
	} else if !knownPort(network.DstPort) {
		add("network.dst_port", "out_of_range", QualityMissingDstPort)
	}
	if strings.TrimSpace(network.Proto) == "" {
		add("network.proto", "missing", QualityMissingProtocol)
	}

	if len(report.Issues) > 0 {
		report.SuggestedFlags = append(report.SuggestedFlags, QualityInsufficientTelemetry)
	}
	report.Complete = len(report.Issues) == 0
	return report
}

// ApplyNetworkFieldFlags records the report on the event. It is idempotent so
// re-ingesting the same payload does not accumulate duplicates.
func (event *EventV2) ApplyNetworkFieldFlags() NetworkFieldReport {
	report := event.NetworkFieldReport()
	if !report.IsNetwork {
		return report
	}
	for _, flag := range report.SuggestedFlags {
		event.addQualityFlag(flag)
	}
	return report
}

func (event *EventV2) addQualityFlag(flag QualityFlag) {
	if flag == "" {
		return
	}
	for _, existing := range event.QualityFlags {
		if existing == flag {
			return
		}
	}
	event.QualityFlags = append(event.QualityFlags, flag)
}

// ContractValidationError is a structured rejection that names the field and
// the reason, so API callers can act on it instead of parsing prose.
type ContractValidationError struct {
	Code   string
	Field  string
	Reason string
}

func (err *ContractValidationError) Error() string {
	return fmt.Sprintf("security event v2: %s (%s: %s)", err.Code, err.Field, err.Reason)
}

// ValidateWithMode runs the base contract first, then applies network field
// completeness according to the mode:
//
//	off      base contract only
//	shadow   base contract only; callers apply flags and log the gap
//	enforce  reject incomplete network events with a structured error
func (event EventV2) ValidateWithMode(mode FieldValidationMode) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if mode == "" || mode == FieldValidationOff || mode == FieldValidationShadow {
		return nil
	}
	report := event.NetworkFieldReport()
	if !report.IsNetwork || report.Complete {
		return nil
	}
	first := report.Issues[0]
	return &ContractValidationError{
		Code:   "insufficient_telemetry",
		Field:  first.Field,
		Reason: first.Reason,
	}
}

// IsInsufficientTelemetry reports whether the event carries the quality flag
// that rules must use to avoid matching on a missing field.
func (event EventV2) IsInsufficientTelemetry() bool {
	return event.HasQualityFlag(QualityInsufficientTelemetry)
}

// HasQualityFlag reports whether the event carries the given quality flag.
func (event EventV2) HasQualityFlag(flag QualityFlag) bool {
	for _, existing := range event.QualityFlags {
		if existing == flag {
			return true
		}
	}
	return false
}
