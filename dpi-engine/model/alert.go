package model

import "time"

type Alert struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Signature string    `json:"signature"`
	Category  string    `json:"category"`
	Severity  uint8     `json:"severity"`
	Score     int       `json:"risk_score"`
	Status    string    `json:"status"`
	SensorID  string    `json:"sensor_id"`
	Domain    string    `json:"domain,omitempty"`
}

const (
	AlertSeverityCritical uint8 = 1
	AlertSeverityHigh     uint8 = 2
	AlertSeverityMedium   uint8 = 3
	AlertSeverityLow      uint8 = 4
)

const (
	AlertTypeDPI      = "dpi"
	AlertTypeLog      = "log"
	AlertTypeEndpoint = "endpoint"
)

const (
	CategoryMining     = "mining"
	CategoryFraud      = "fraud"
	CategoryDGA        = "dga"
	CategoryDNSTunnel  = "dns_tunnel"
	CategorySuspicious = "suspicious"
	CategoryMalware    = "malware"
)

const (
	StatusNew     = "new"
	StatusHandled = "handled"
	StatusIgnored = "ignored"
)

func (a *Alert) FromFlow(flow *FlowData) {
	a.Timestamp = time.Now()
	a.SrcIP = flow.SrcIP
	a.DstIP = flow.DstIP
	a.SrcPort = flow.SrcPort
	a.DstPort = flow.DstPort
	a.Protocol = flow.Protocol
	a.SensorID = flow.SensorID
	a.Domain = flow.GetDomain()
}

func SeverityToString(s uint8) string {
	switch s {
	case 1:
		return "critical"
	case 2:
		return "high"
	case 3:
		return "medium"
	default:
		return "low"
	}
}
