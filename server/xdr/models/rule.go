package models

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Rule XDR 规则结构
type Rule struct {
	ID             int      `yaml:"id"`              // 规则 ID
	Name           string   `yaml:"name"`            // 规则名称
	Level          int      `yaml:"level"`           // 告警级别 (0-15)
	Source         string   `yaml:"source"`          // 日志来源: sshd/nginx/mysql
	Match          string   `yaml:"match"`           // 匹配模式（正则或字符串）
	IsRegex        bool     `yaml:"regex"`           // 是否为正则表达式
	NotMatch       string   `yaml:"not_match"`       // 排除模式
	IfSID          int      `yaml:"if_sid"`          // 父规则 ID（用于关联分析）
	Frequency      int      `yaml:"frequency"`       // 触发频率
	Timeframe      int      `yaml:"timeframe"`       // 时间窗口（秒）
	SameSrcip      bool     `yaml:"same_srcip"`      // 相同源 IP
	SameUser       bool     `yaml:"same_user"`       // 相同用户
	Description    string   `yaml:"description"`     // 规则描述
	Mitre          []string `yaml:"mitre"`           // MITRE ATT&CK ID 列表
	MitreTactic    string   `yaml:"mitre_tactic"`    // MITRE 战术
	MitreTechnique string   `yaml:"mitre_technique"` // MITRE 技术
	Groups         []string `yaml:"groups"`          // 规则组
	Info           []Info   `yaml:"info"`            // 额外信息 (CVE/链接等)
	Enabled        bool     `yaml:"enabled"`         // 是否启用
	Overwrite      bool     `yaml:"overwrite"`       // 是否覆盖原有规则
	Ignore         int      `yaml:"ignore"`          // 忽略时间（秒）
	NoAlert        bool     `yaml:"noalert"`         // 不生成告警
	SrcIP          string   `yaml:"srcip"`           // 匹配源 IP
	DstIP          string   `yaml:"dstip"`           // 匹配目标 IP
	User           string   `yaml:"user"`            // 匹配用户
	Program        string   `yaml:"program"`         // 匹配程序
	ExtraData      string   `yaml:"extra_data"`      // 额外数据字段
	Category       string   `yaml:"category"`        // 规则分类
	Plugin         string   `yaml:"plugin"`          // 插件名称
}

// Info 规则额外信息
type Info struct {
	Type  string `yaml:"type"`  // info 类型: link/cve/text/cwe
	Value string `yaml:"value"` // 信息值
}

// RuleSet 规则集
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// MatchResult 匹配结果
type MatchResult struct {
	Rule      *Rule          `json:"rule"`
	Log       *NormalizedLog `json:"log"`
	MatchTime time.Time      `json:"match_time"`
}

// RuleEngine 规则引擎配置
type RuleEngineConfig struct {
	RulesDir       string `yaml:"rules_dir"`       // 规则目录
	EnabledFile    string `yaml:"enabled_file"`    // 启用的规则文件
	ReloadInterval int    `yaml:"reload_interval"` // 重载间隔（秒）
}

// RuleStats 规则统计
type RuleStats struct {
	TotalRules    int            `json:"total_rules"`
	EnabledRules  int            `json:"enabled_rules"`
	DisabledRules int            `json:"disabled_rules"`
	ByLevel       map[int]int    `json:"by_level"`
	BySource      map[string]int `json:"by_source"`
	ByGroup       map[string]int `json:"by_group"`
}

// Match 匹配规则
func (r *Rule) Evaluate(log *NormalizedLog) (bool, map[string]string) {
	// 检查来源
	if r.Source != "" && r.Source != log.Source && r.Source != log.Program {
		return false, nil
	}

	// 检查程序名
	if r.Program != "" && r.Program != log.Program {
		return false, nil
	}

	// 检查用户
	if r.User != "" && r.User != log.User {
		return false, nil
	}

	// 检查源 IP
	if r.SrcIP != "" && r.SrcIP != log.SrcIP {
		return false, nil
	}

	// 检查目标 IP
	if r.DstIP != "" && r.DstIP != log.DstIP {
		return false, nil
	}

	searchText := r.searchText(log)

	// 检查匹配模式
	if r.Match != "" {
		matched := false
		if r.IsRegex || looksLikeRegex(r.Match) {
			matched = r.matchRegex(searchText)
		} else {
			matched = strings.Contains(searchText, r.Match)
		}
		if !matched {
			return false, nil
		}
	}

	// 检查排除模式
	if r.NotMatch != "" {
		if r.IsRegex {
			if r.matchRegex(searchText) {
				return false, nil
			}
		} else {
			if strings.Contains(searchText, r.NotMatch) {
				return false, nil
			}
		}
	}

	// 提取字段
	fields := r.extractFields(log)

	return true, fields
}

func (r *Rule) searchText(log *NormalizedLog) string {
	if log == nil {
		return ""
	}
	parts := []string{
		log.Message,
		log.Raw,
		log.Source,
		log.Program,
		log.Service,
		log.User,
		log.SrcIP,
		log.DstIP,
		log.Hostname,
	}
	for key, value := range log.Metadata {
		parts = append(parts, key, fmt.Sprintf("%v", value))
	}
	return strings.Join(parts, " ")
}

func looksLikeRegex(pattern string) bool {
	return strings.ContainsAny(pattern, "|^$()[]+*?")
}

// matchRegex 执行正则匹配
func (r *Rule) matchRegex(text string) bool {
	// 缓存编译的正则表达式
	pattern := r.Match
	if strings.HasPrefix(pattern, "^") || strings.Contains(pattern, "(") {
		// 已经是完整正则
	} else {
		// 添加模糊匹配
		pattern = "(?i)" + pattern
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(text)
}

// extractFields 从日志中提取字段
func (r *Rule) extractFields(log *NormalizedLog) map[string]string {
	fields := make(map[string]string)

	// 提取 IP 地址
	fields["srcip"] = log.SrcIP
	fields["dstip"] = log.DstIP
	fields["src_port"] = fmt.Sprintf("%d", log.SrcPort)
	fields["dst_port"] = fmt.Sprintf("%d", log.DstPort)
	fields["user"] = log.User
	fields["hostname"] = log.Hostname
	fields["program_name"] = log.Program
	fields["service"] = log.Service

	return fields
}

// GetSeverity 将 level 转换为 severity
func (r *Rule) GetSeverity() string {
	switch {
	case r.Level >= 10:
		return SeverityCritical
	case r.Level >= 7:
		return SeverityHigh
	case r.Level >= 4:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// GetEventType 生成事件类型
func (r *Rule) GetEventType() string {
	source := r.Source
	if source == "" {
		source = "unknown"
	}
	// 转换规则名为事件类型格式: ssh_brute_force
	name := strings.ToLower(r.Name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ":", "")
	return fmt.Sprintf("xdr.%s.%s", source, name)
}

// GetMitreTactic 获取 MITRE 战术
func (r *Rule) GetMitreTactic() string {
	if len(r.Mitre) > 0 {
		return r.Mitre[0]
	}
	return r.MitreTactic
}

// GetMitreTechnique 获取 MITRE 技术
func (r *Rule) GetMitreTechnique() string {
	if len(r.Mitre) > 1 {
		return r.Mitre[1]
	}
	return r.MitreTechnique
}

// GetTags 获取标签
func (r *Rule) GetTags() []string {
	tags := make([]string, 0)
	tags = append(tags, r.Groups...)
	if len(r.Mitre) > 0 {
		tags = append(tags, r.Mitre...)
	}
	tags = append(tags, fmt.Sprintf("xdr_%s", r.Source))
	return tags
}
