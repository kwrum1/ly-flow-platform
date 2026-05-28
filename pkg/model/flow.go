package model

import (
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
	HTTPHost    string `json:"http_host,omitempty"`
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
