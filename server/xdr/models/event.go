package models

import (
	"encoding/json"
	"time"
)

// XDREvent XDR 事件结构 - 与 DPI Event 统一格式
type XDREvent struct {
	ID              int64     `json:"id"`                // 事件 ID
	EventType       string    `json:"event_type"`         // 事件类型: xdr.ssh.brute_force
	Source          string    `json:"source"`             // 来源: xdr-log-collector
	Severity        string    `json:"severity"`           // 严重程度: low/medium/high/critical
	AgentID         string    `json:"agent_id"`           // Agent ID
	Hostname        string    `json:"hostname"`           // 主机名
	Message         string    `json:"message"`            // 告警消息
	SrcIP           string    `json:"src_ip"`             // 源 IP
	DstIP           string    `json:"dst_ip"`             // 目标 IP
	SrcPort         int       `json:"src_port"`           // 源端口
	DstPort         int       `json:"dst_port"`           // 目标端口
	User            string    `json:"user"`               // 用户名
	Service         string    `json:"service"`            // 服务名
	RawLog          string    `json:"raw_log"`            // 原始日志
	RuleID          int       `json:"rule_id"`            // 触发规则 ID
	RuleName        string    `json:"rule_name"`         // 触发规则名称
	MitreTactic     string    `json:"mitre_tactic"`       // MITRE ATT&CK 战术
	MitreTechnique  string    `json:"mitre_technique"`   // MITRE ATT&CK 技术
	Tags            []string  `json:"tags"`              // 标签
	LogSource       string    `json:"log_source"`        // 日志来源
	Frequency       int       `json:"frequency"`         // 触发次数（频率关联用）
	CreatedAt       time.Time `json:"created_at"`         // 创建时间
}

// Severity 严重程度常量
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// LevelToSeverity 将日志级别转换为严重程度
func LevelToSeverity(level string) string {
	switch level {
	case "critical", "0", "1":
		return SeverityCritical
	case "error", "2", "3":
		return SeverityHigh
	case "warning", "4", "5", "6":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// XDREventInput XDR 事件输入
type XDREventInput struct {
	EventType   string
	Severity    string
	AgentID     string
	Hostname    string
	Message     string
	SrcIP       string
	DstIP       string
	SrcPort     int
	DstPort     int
	User        string
	Service     string
	RawLog      string
	RuleID      int
	RuleName    string
	MitreTactic string
	MitreTechnique string
	Tags        []string
	LogSource   string
	Frequency   int
}

// ToXDREvent 转换为 XDR 事件
func (i *XDREventInput) ToXDREvent() *XDREvent {
	return &XDREvent{
		EventType:      i.EventType,
		Source:         "xdr-log-collector",
		Severity:       i.Severity,
		AgentID:        i.AgentID,
		Hostname:       i.Hostname,
		Message:        i.Message,
		SrcIP:          i.SrcIP,
		DstIP:          i.DstIP,
		SrcPort:        i.SrcPort,
		DstPort:        i.DstPort,
		User:           i.User,
		Service:        i.Service,
		RawLog:         i.RawLog,
		RuleID:         i.RuleID,
		RuleName:       i.RuleName,
		MitreTactic:    i.MitreTactic,
		MitreTechnique: i.MitreTechnique,
		Tags:           i.Tags,
		LogSource:      i.LogSource,
		Frequency:      i.Frequency,
		CreatedAt:      time.Now(),
	}
}

// ToJSON 序列化为 JSON
func (e *XDREvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// XDREventList XDR 事件列表响应
type XDREventList struct {
	Items  []*XDREvent `json:"items"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// XDREventStats XDR 事件统计
type XDREventStats struct {
	TotalEvents      int64            `json:"total_events"`
	TotalAlerts     int64            `json:"total_alerts"`
	CriticalAlerts  int64            `json:"critical_alerts"`
	HighAlerts      int64            `json:"high_alerts"`
	MediumAlerts    int64            `json:"medium_alerts"`
	LowAlerts       int64            `json:"low_alerts"`
	EventsToday     int64            `json:"events_today"`
	AlertsToday     int64            `json:"alerts_today"`
	TopSources      map[string]int64 `json:"top_sources"`
	TopRules        map[string]int64 `json:"top_rules"`
	TopSrcIPs       map[string]int64 `json:"top_src_ips"`
	AlertsByHour    []int64          `json:"alerts_by_hour"`
	Sources         []string         `json:"sources"`
}
