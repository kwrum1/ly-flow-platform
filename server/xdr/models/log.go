package models

import (
	"time"
)

// NormalizedLog 归一化日志结构 - 统一不同来源的日志格式
type NormalizedLog struct {
	ID        uint64                 `json:"id"`        // 日志 ID
	Timestamp time.Time              `json:"timestamp"` // 日志时间
	AgentID   string                 `json:"agent_id"`  // Agent ID
	Hostname  string                 `json:"hostname"`  // 主机名
	Source    string                 `json:"source"`    // 日志来源: sshd/nginx/mysql/systemd/auditd
	Program   string                 `json:"program"`   // 程序名称
	Level     string                 `json:"level"`     // 日志级别: info/warning/error/critical
	Message   string                 `json:"message"`   // 日志消息
	SrcIP     string                 `json:"src_ip"`    // 源 IP
	DstIP     string                 `json:"dst_ip"`    // 目标 IP
	SrcPort   int                    `json:"src_port"`  // 源端口
	DstPort   int                    `json:"dst_port"`  // 目标端口
	User      string                 `json:"user"`      // 用户名
	Service   string                 `json:"service"`   // 服务名
	Raw       string                 `json:"raw"`       // 原始日志
	Metadata  map[string]interface{} `json:"metadata"`  // 额外元数据
}

// NewNormalizedLog 创建归一化日志
func NewNormalizedLog() *NormalizedLog {
	return &NormalizedLog{
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
}

// LogSource 日志来源类型
type LogSource string

const (
	SourceSSH      LogSource = "sshd"
	SourceNginx    LogSource = "nginx"
	SourceMySQL    LogSource = "mysql"
	SourceSystemd  LogSource = "systemd"
	SourceAuditd   LogSource = "auditd"
	SourceApache   LogSource = "apache"
	SourcePostgres LogSource = "postgresql"
	SourcePAM      LogSource = "pam"
	SourceUnknown  LogSource = "unknown"
)

// LogLevel 日志级别
type LogLevel string

const (
	LevelInfo     LogLevel = "info"
	LevelWarning  LogLevel = "warning"
	LevelError    LogLevel = "error"
	LevelCritical LogLevel = "critical"
	LevelDebug    LogLevel = "debug"
)

// XDRLogInput XDR 日志输入（用于 API 接收）
type XDRLogInput struct {
	AgentID   string                 `json:"agent_id"`
	Hostname  string                 `json:"hostname"`
	Source    string                 `json:"source"`
	Program   string                 `json:"program"`
	Level     string                 `json:"level"`
	Timestamp string                 `json:"timestamp"`
	Message   string                 `json:"message"`
	SrcIP     string                 `json:"src_ip"`
	DstIP     string                 `json:"dst_ip"`
	SrcPort   int                    `json:"src_port"`
	DstPort   int                    `json:"dst_port"`
	User      string                 `json:"user"`
	Service   string                 `json:"service"`
	Raw       string                 `json:"raw"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ToNormalizedLog 转换为归一化日志
func (l *XDRLogInput) ToNormalizedLog() (*NormalizedLog, error) {
	ts := time.Now()
	if l.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, l.Timestamp); err == nil {
			ts = parsed
		}
	}

	return &NormalizedLog{
		ID:        0,
		Timestamp: ts,
		AgentID:   l.AgentID,
		Hostname:  l.Hostname,
		Source:    l.Source,
		Program:   l.Program,
		Level:     l.Level,
		Message:   l.Message,
		SrcIP:     l.SrcIP,
		DstIP:     l.DstIP,
		SrcPort:   l.SrcPort,
		DstPort:   l.DstPort,
		User:      l.User,
		Service:   l.Service,
		Raw:       l.Raw,
		Metadata:  l.Metadata,
	}, nil
}
