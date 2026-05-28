package model

import (
	"strings"
	"time"
)

// FlowData represents a network flow record sent from ly-agent to flows:raw
type FlowData struct {
	ID          string `json:"id"`
	Timestamp   int64  `json:"timestamp"`
	SensorID    string `json:"sensor_id"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	AppProtocol string `json:"app_protocol"`
	DNSQuery    string `json:"dns_query,omitempty"`
	DNSAnswer   string `json:"dns_answer,omitempty"`
	DNSDomain   string `json:"dns_domain,omitempty"`
	HTTPHost    string `json:"http_host,omitempty"`
	HTTPMethod  string `json:"http_method,omitempty"`
	HTTPPath    string `json:"http_path,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	TLSSNI      string `json:"tls_sni,omitempty"`
	JA3         string `json:"ja3,omitempty"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
	Packets     uint64 `json:"packets"`
	DurationMs  uint64 `json:"duration_ms"`
	Direction   string `json:"direction"`
}

// Time returns the flow timestamp as time.Time
func (f *FlowData) Time() time.Time {
	return time.Unix(f.Timestamp, 0)
}

// GetDomain returns the domain from TLS SNI, HTTP Host, or DNS query (in that order)
func (f *FlowData) GetDomain() string {
	if f.TLSSNI != "" {
		return f.TLSSNI
	}
	if f.HTTPHost != "" {
		return f.HTTPHost
	}
	return f.DNSQuery
}

// Flow is an alias for FlowData for backward compatibility
type Flow = FlowData

type RawFlow = FlowData

type SemanticFlow struct {
	SchemaVersion string `json:"schema_version"`
	SourceStream  string `json:"source_stream"`
	FlowID        string `json:"flow_id"`
	SessionID     string `json:"session_id,omitempty"`
	Timestamp     int64  `json:"timestamp"`
	SensorID      string `json:"sensor_id"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	Transport     string `json:"transport"`
	AppProtocol   string `json:"app_protocol"`
	Domain        string `json:"domain,omitempty"`
	DNSQuery      string `json:"dns_query,omitempty"`
	DNSAnswer     string `json:"dns_answer,omitempty"`
	DNSDomain     string `json:"dns_domain,omitempty"`
	HTTPHost      string `json:"http_host,omitempty"`
	TLSSNI        string `json:"tls_sni,omitempty"`
	JA3           string `json:"ja3,omitempty"`
	HTTPMethod    string `json:"http_method,omitempty"`
	HTTPPath      string `json:"http_path,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	TLSSerial     string `json:"tls_serial,omitempty"`
	RiskScore     int    `json:"risk_score,omitempty"`
	RiskLevel     string `json:"risk_level,omitempty"`
	ThreatType    string `json:"threat_type,omitempty"`
	Context       string `json:"context,omitempty"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	Packets       uint64 `json:"packets"`
	DurationMs    uint64 `json:"duration_ms,omitempty"`
	Direction     string `json:"direction"`
}

type SemanticSession struct {
	SchemaVersion      string `json:"schema_version"`
	SourceStream       string `json:"source_stream"`
	SessionID          string `json:"session_id"`
	FlowID             string `json:"flow_id"`
	StartedAt          int64  `json:"started_at"`
	LastSeenAt         int64  `json:"last_seen_at"`
	SensorID           string `json:"sensor_id"`
	SrcIP              string `json:"src_ip"`
	DstIP              string `json:"dst_ip"`
	SrcPort            uint16 `json:"src_port"`
	DstPort            uint16 `json:"dst_port"`
	Transport          string `json:"transport"`
	AppProtocol        string `json:"app_protocol"`
	Domain             string `json:"domain,omitempty"`
	DNSQuery           string `json:"dns_query,omitempty"`
	DNSAnswer          string `json:"dns_answer,omitempty"`
	DNSDomain          string `json:"dns_domain,omitempty"`
	HTTPHost           string `json:"http_host,omitempty"`
	TLSSNI             string `json:"tls_sni,omitempty"`
	JA3                string `json:"ja3,omitempty"`
	FlowCount          uint64 `json:"flow_count"`
	BytesIn            uint64 `json:"bytes_in"`
	BytesOut           uint64 `json:"bytes_out"`
	Packets            uint64 `json:"packets"`
	DurationMs         uint64 `json:"duration_ms"`
	Direction          string `json:"direction"`
	RiskScore          int    `json:"risk_score,omitempty"`
	RiskLevel          string `json:"risk_level,omitempty"`
	BehaviorSummary    string `json:"behavior_summary,omitempty"`
	SuspectedBot       bool   `json:"suspected_bot,omitempty"`
	RepeatedDomainHits uint32 `json:"repeated_domain_hits,omitempty"`
}

func (f *FlowData) ToSemanticFlow() *SemanticFlow {
	if f == nil {
		return nil
	}
	return &SemanticFlow{
		SchemaVersion: "v1",
		SourceStream:  "flows:raw",
		FlowID:        f.ID,
		SessionID:     f.ID,
		Timestamp:     f.Timestamp,
		SensorID:      f.SensorID,
		SrcIP:         f.SrcIP,
		DstIP:         f.DstIP,
		SrcPort:       f.SrcPort,
		DstPort:       f.DstPort,
		Transport:     f.Protocol,
		AppProtocol:   f.AppProtocol,
		Domain:        f.GetDomain(),
		DNSQuery:      f.DNSQuery,
		DNSAnswer:     f.DNSAnswer,
		DNSDomain:     f.DNSDomain,
		HTTPHost:      f.HTTPHost,
		HTTPMethod:    f.HTTPMethod,
		HTTPPath:      f.HTTPPath,
		HTTPStatus:    f.HTTPStatus,
		TLSSNI:        f.TLSSNI,
		JA3:           f.JA3,
		BytesIn:       f.BytesIn,
		BytesOut:      f.BytesOut,
		Packets:       f.Packets,
		DurationMs:    f.DurationMs,
		Direction:     f.Direction,
	}
}

func (f *FlowData) ToSemanticSession() *SemanticSession {
	if f == nil {
		return nil
	}
	behaviorSummary, suspectedBot, repeatedDomainHits := f.deriveBehavior()
	return &SemanticSession{
		SchemaVersion:      "v1",
		SourceStream:       "flows:semantic",
		SessionID:          f.ID,
		FlowID:             f.ID,
		StartedAt:          f.Timestamp,
		LastSeenAt:         f.Timestamp,
		SensorID:           f.SensorID,
		SrcIP:              f.SrcIP,
		DstIP:              f.DstIP,
		SrcPort:            f.SrcPort,
		DstPort:            f.DstPort,
		Transport:          f.Protocol,
		AppProtocol:        f.AppProtocol,
		Domain:             f.GetDomain(),
		DNSQuery:           f.DNSQuery,
		DNSAnswer:          f.DNSAnswer,
		DNSDomain:          f.DNSDomain,
		HTTPHost:           f.HTTPHost,
		TLSSNI:             f.TLSSNI,
		JA3:                f.JA3,
		FlowCount:          1,
		BytesIn:            f.BytesIn,
		BytesOut:           f.BytesOut,
		Packets:            f.Packets,
		DurationMs:         f.DurationMs,
		Direction:          f.Direction,
		BehaviorSummary:    behaviorSummary,
		SuspectedBot:       suspectedBot,
		RepeatedDomainHits: repeatedDomainHits,
	}
}

func (f *FlowData) deriveBehavior() (string, bool, uint32) {
	domain := strings.TrimSpace(f.GetDomain())
	suspectedBot := strings.Contains(strings.ToLower(domain), "bot") || f.JA3 != ""
	repeatedDomainHits := uint32(0)
	if domain != "" {
		repeatedDomainHits = 1
	}
	behaviorSummary := "single_flow"
	if f.AppProtocol != "" {
		behaviorSummary = strings.ToLower(f.AppProtocol) + "_single_flow"
	}
	if domain != "" {
		behaviorSummary += "_domain"
	}
	return behaviorSummary, suspectedBot, repeatedDomainHits
}

// Example FlowData JSON:
// {
//   "id": "uuid-string",
//   "timestamp": 1715123456,
//   "sensor_id": "agent-uuid",
//   "src_ip": "192.168.1.100",
//   "dst_ip": "8.8.8.8",
//   "src_port": 54321,
//   "dst_port": 443,
//   "protocol": "TCP",
//   "app_protocol": "HTTPS",
//   "tls_sni": "malicious-domain.com",
//   "ja3": "d4e4f0a2...",
//   "bytes_in": 1024,
//   "bytes_out": 2048,
//   "packets": 10,
//   "duration_ms": 500,
//   "direction": "egress"
// }
