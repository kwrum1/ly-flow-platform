package model

import (
	"time"
)

// Event represents a normalized security event stored in PostgreSQL
type Event struct {
	ID             int64     `json:"id" db:"id"`
	Timestamp      time.Time `json:"timestamp" db:"timestamp"`
	EventType      string    `json:"event_type" db:"event_type"`
	Source         string    `json:"source" db:"source"`
	Severity       string    `json:"severity" db:"severity"`
	SrcIP          string    `json:"src_ip" db:"src_ip"`
	DstIP          string    `json:"dst_ip" db:"dst_ip"`
	SrcPort        int       `json:"src_port" db:"src_port"`
	DstPort        int       `json:"dst_port" db:"dst_port"`
	Protocol       string    `json:"protocol" db:"protocol"`
	Domain         string    `json:"domain" db:"domain"`
	Tags           []string  `json:"tags" db:"tags"`
	MitreTactic    string    `json:"mitre_tactic" db:"mitre_tactic"`
	MitreTechnique string    `json:"mitre_technique" db:"mitre_technique"`
	RawData        []byte    `json:"raw_data" db:"raw_data"`
	Metadata       []byte    `json:"metadata" db:"metadata"`
	Status         string    `json:"status" db:"status"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// Event types
const (
	EventTypeDPI      = "dpi"
	EventTypeLog      = "log"
	EventTypeEndpoint = "endpoint"
	EventTypeAsset    = "asset"
	EventTypeVuln     = "vulnerability"
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// FromAlert converts an Alert to Event
func (e *Event) FromAlert(alert *Alert) {
	e.Timestamp = alert.Timestamp
	e.EventType = alert.Type
	e.Source = "dpi-engine"
	e.Severity = SeverityFromUint8(alert.Severity)
	e.SrcIP = alert.SrcIP
	e.DstIP = alert.DstIP
	e.SrcPort = int(alert.SrcPort)
	e.DstPort = int(alert.DstPort)
	e.Protocol = alert.Protocol
	e.Domain = alert.Domain
	e.Tags = []string{alert.Category}
	e.Status = alert.Status
}

// SeverityFromUint8 converts uint8 severity to string
func SeverityFromUint8(s uint8) string {
	switch s {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
