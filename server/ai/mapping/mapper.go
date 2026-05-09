package mapping

import (
	"fmt"
	"ly-flow-platform/pkg/model"
)

// Mapper 告警映射器
type Mapper struct {
	rules map[string]*MappingRule
}

// MappingRule 映射规则
type MappingRule struct {
	Category   string
	Severity   string
	Signature  string
	TechniqueID string
	SubTechniqueID string
	Confidence float64
	ExtractFunc func(*model.Alert) []string
}

// NewMapper 创建新的映射器
func NewMapper() *Mapper {
	m := &Mapper{
		rules: make(map[string]*MappingRule),
	}
	m.loadDefaultRules()
	return m
}

// loadDefaultRules 加载默认规则
func (m *Mapper) loadDefaultRules() {
	rules := GetDefaultRules()
	for _, rule := range rules {
		key := m.makeKey(rule.Category, rule.Severity, rule.Signature)
		m.rules[key] = &rule
	}
}

// makeKey 生成规则键
func (m *Mapper) makeKey(category, severity, signature string) string {
	return fmt.Sprintf("%s:%s:%s", category, severity, signature)
}

// Map 将告警映射到 ATT&CK 技术
func (m *Mapper) Map(alert *model.Alert) *AttackStep {
	if alert == nil {
		return nil
	}

	// 精确匹配 category + severity + signature
	key := m.makeKey(alert.Category, m.severityToStr(alert.Severity), alert.Signature)
	if rule, ok := m.rules[key]; ok {
		return m.createStep(alert, rule)
	}

	// 匹配 category + severity
	key = m.makeKey(alert.Category, m.severityToStr(alert.Severity), "")
	if rule, ok := m.rules[key]; ok {
		return m.createStep(alert, rule)
	}

	// 匹配 category
	key = m.makeKey(alert.Category, "", "")
	if rule, ok := m.rules[key]; ok {
		return m.createStep(alert, rule)
	}

	// 根据 category 推断技术
	return m.inferTechnique(alert)
}

// createStep 创建攻击步骤
func (m *Mapper) createStep(alert *model.Alert, rule *MappingRule) *AttackStep {
	var technique *Technique
	if rule.SubTechniqueID != "" {
		technique = GetTechnique(rule.SubTechniqueID)
		if technique == nil {
			technique = GetTechnique(rule.TechniqueID)
		}
	} else {
		technique = GetTechnique(rule.TechniqueID)
	}

	if technique == nil {
		return nil
	}

	evidence := []string{
		fmt.Sprintf("告警类别: %s", alert.Category),
		fmt.Sprintf("告警签名: %s", alert.Signature),
	}

	// 如果有提取函数，获取额外证据
	if rule.ExtractFunc != nil {
		evidence = append(evidence, rule.ExtractFunc(alert)...)
	}

	return &AttackStep{
		ID:         fmt.Sprintf("%s-%d", technique.ID, alert.ID),
		Technique:  technique,
		Alert:      alert,
		Timestamp:  alert.Timestamp,
		Confidence: rule.Confidence,
		Evidence:   evidence,
	}
}

// inferTechnique 根据告警类别推断技术
func (m *Mapper) inferTechnique(alert *model.Alert) *AttackStep {
	// 基于 category 的默认映射
	categoryMapping := map[string]string{
		"mining":    "T1490",
		"dns_tunnel": "T1071.004",
		"dga":       "T1102",
		"fraud":     "T1566",
		"sql_injection": "T1059",
		"suspicious": "T1059",
		"malware":   "T1059",
	}

	techniqueID, ok := categoryMapping[alert.Category]
	if !ok {
		return nil
	}

	technique := GetTechnique(techniqueID)
	if technique == nil {
		return nil
	}

	confidence := 0.6 // 默认置信度
	if alert.Severity <= model.SeverityHigh {
		confidence = 0.8
	}

	evidence := []string{
		fmt.Sprintf("告警类别: %s", alert.Category),
		fmt.Sprintf("告警签名: %s", alert.Signature),
		fmt.Sprintf("严重程度: %d", alert.Severity),
	}

	if alert.Domain != "" {
		evidence = append(evidence, fmt.Sprintf("关联域名: %s", alert.Domain))
	}

	return &AttackStep{
		ID:         fmt.Sprintf("%s-%d", technique.ID, alert.ID),
		Technique:  technique,
		Alert:      alert,
		Timestamp:  alert.Timestamp,
		Confidence: confidence,
		Evidence:   evidence,
	}
}

// severityToStr 将严重程度转换为字符串
func (m *Mapper) severityToStr(severity uint8) string {
	switch severity {
	case model.SeverityCritical:
		return "critical"
	case model.SeverityHigh:
		return "high"
	case model.SeverityMedium:
		return "medium"
	case model.SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// LoadRules 加载自定义规则
func (m *Mapper) LoadRules(rules []MappingRule) {
	for _, rule := range rules {
		key := m.makeKey(rule.Category, rule.Severity, rule.Signature)
		m.rules[key] = &rule
	}
}

// GetRules 返回当前所有规则
func (m *Mapper) GetRules() []*MappingRule {
	var rules []*MappingRule
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	return rules
}

// CategoryInferenceRules 类别推断规则
var CategoryInferenceRules = map[string]struct {
	TechniqueID string
	SubTechniqueID string
	MinSeverity uint8
}{
	"mining":       {TechniqueID: "T1490", MinSeverity: model.SeverityHigh},
	"dns_tunnel":   {TechniqueID: "T1071", SubTechniqueID: "T1071.004", MinSeverity: model.SeverityHigh},
	"dga":          {TechniqueID: "T1102", SubTechniqueID: "T1102.002", MinSeverity: model.SeverityMedium},
	"fraud":        {TechniqueID: "T1566", MinSeverity: model.SeverityHigh},
	"sql_injection": {TechniqueID: "T1059", MinSeverity: model.SeverityHigh},
	"xss":          {TechniqueID: "T1059", MinSeverity: model.SeverityMedium},
	"webshell":     {TechniqueID: "T1059", SubTechniqueID: "T1059.001", MinSeverity: model.SeverityHigh},
	"backdoor":     {TechniqueID: "T1059", MinSeverity: model.SeverityHigh},
	"ransomware":   {TechniqueID: "T1486", MinSeverity: model.SeverityCritical},
	"bruteforce":   {TechniqueID: "T1110", MinSeverity: model.SeverityHigh},
}