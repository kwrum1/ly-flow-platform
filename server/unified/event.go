package unified

import (
	"encoding/json"
	"time"
)

// ModuleType 模块类型
type ModuleType string

const (
	ModuleDPI      ModuleType = "dpi"
	ModuleXDR      ModuleType = "xdr"
	ModuleRASP     ModuleType = "rasp"
	ModuleRuntime  ModuleType = "runtime"
	ModuleLog      ModuleType = "log"
	ModuleVuln     ModuleType = "vuln"
	ModuleAsset    ModuleType = "asset"
	ModuleBaseline ModuleType = "baseline"
	ModuleTrace    ModuleType = "trace"
)

// Severity 严重程度
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// EventStatus 事件状态
type EventStatus string

const (
	StatusNew       EventStatus = "new"
	StatusProcessed EventStatus = "processed"
	StatusResolved  EventStatus = "resolved"
	StatusIgnored   EventStatus = "ignored"
)

type EntityIDs struct {
	AgentID     string `json:"agent_id,omitempty"`
	HostID      string `json:"host_id,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	ProcessID   string `json:"process_id,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
}

type BehaviorContext struct {
	Scenario   string                 `json:"scenario,omitempty"`
	Action     string                 `json:"action,omitempty"`
	Stage      string                 `json:"stage,omitempty"`
	Confidence float64                `json:"confidence,omitempty"`
	Labels     []string               `json:"labels,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

type RawReference struct {
	Stream       string `json:"stream,omitempty"`
	MessageID    string `json:"message_id,omitempty"`
	PayloadRef   string `json:"payload_ref,omitempty"`
	PayloadHash  string `json:"payload_hash,omitempty"`
	CaptureRef   string `json:"capture_ref,omitempty"`
	CollectorRef string `json:"collector_ref,omitempty"`
}

// UnifiedEvent 统一事件格式 - 所有检测模块的事件统一格式
type UnifiedEvent struct {
	ID              string           `json:"id"`
	SchemaVersion   string           `json:"schema_version,omitempty"`
	Module          ModuleType       `json:"module"`
	SourceModule    ModuleType       `json:"source_module,omitempty"`
	EventType       string           `json:"event_type"`
	Source          string           `json:"source"`
	Severity        Severity         `json:"severity"`
	Timestamp       time.Time        `json:"timestamp"`
	Alert           bool             `json:"alert"`
	EntityIDs       *EntityIDs       `json:"entity_ids,omitempty"`
	BehaviorContext *BehaviorContext `json:"behavior_context,omitempty"`
	RawReference    *RawReference    `json:"raw_reference,omitempty"`

	// 网络信息（可选）
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// 主机信息（可选）
	AgentID  string `json:"agent_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`

	// 应用信息（可选）
	User    string `json:"user,omitempty"`
	Service string `json:"service,omitempty"`
	Path    string `json:"path,omitempty"`

	// 告警信息
	RuleID   int    `json:"rule_id,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	Message  string `json:"message"`

	// 威胁情报
	MitreTactic    string   `json:"mitre_tactic,omitempty"`
	MitreTechnique string   `json:"mitre_technique,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	IocValue       string   `json:"ioc_value,omitempty"`
	IocType        string   `json:"ioc_type,omitempty"`

	// 上下文信息
	RawData  string                 `json:"raw_data,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// 状态
	Status    EventStatus `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
}

// ToJSON 序列化为 JSON
func (e *UnifiedEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// FromJSON 从 JSON 反序列化
func (e *UnifiedEvent) FromJSON(data []byte) error {
	return json.Unmarshal(data, e)
}

// EventStats 事件统计
type EventStats struct {
	TotalEvents int64 `json:"total_events"`
	TodayEvents int64 `json:"today_events"`
	TotalAlerts int64 `json:"total_alerts"`
	TodayAlerts int64 `json:"today_alerts"`

	ByModule   map[ModuleType]int64 `json:"by_module"`
	BySeverity map[Severity]int64   `json:"by_severity"`
	BySource   map[string]int64     `json:"by_source"`
	BySrcIP    map[string]int64     `json:"by_src_ip"`

	CriticalCount int64 `json:"critical_count"`
	HighCount     int64 `json:"high_count"`
	MediumCount   int64 `json:"medium_count"`
	LowCount      int64 `json:"low_count"`

	NewAlerts      int64 `json:"new_alerts"`
	ResolvedAlerts int64 `json:"resolved_alerts"`
}

// EventList 事件列表响应
type EventList struct {
	Items  []*UnifiedEvent `json:"items"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

// EventSearch 事件搜索请求
type EventSearch struct {
	Query     string      `json:"query,omitempty"`
	Module    ModuleType  `json:"module,omitempty"`
	Severity  Severity    `json:"severity,omitempty"`
	SrcIP     string      `json:"src_ip,omitempty"`
	DstIP     string      `json:"dst_ip,omitempty"`
	AgentID   string      `json:"agent_id,omitempty"`
	Hostname  string      `json:"hostname,omitempty"`
	EventType string      `json:"event_type,omitempty"`
	StartTime string      `json:"start_time,omitempty"`
	EndTime   string      `json:"end_time,omitempty"`
	Tags      []string    `json:"tags,omitempty"`
	Status    EventStatus `json:"status,omitempty"`
	Limit     int         `json:"limit,omitempty"`
	Offset    int         `json:"offset,omitempty"`
}

// EventBatchQuery 批量查询
type EventBatchQuery struct {
	IDs      []string     `json:"ids,omitempty"`
	Modules  []ModuleType `json:"modules,omitempty"`
	Severity []Severity   `json:"severity,omitempty"`
	Limit    int          `json:"limit,omitempty"`
}
