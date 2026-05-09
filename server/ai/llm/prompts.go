package llm

import (
	"ly-flow-platform/pkg/model"
)

// AlertAnalysisPrompt is the prompt template for analyzing individual alerts
const AlertAnalysisPrompt = `你是一个安全分析师。请分析以下告警，判断是否为真实威胁。

告警信息：
- 类型: %s
- 严重级别: %s
- 源IP: %s
- 目标IP: %s
- 域名: %s
- 签名: %s

请输出JSON格式：
{
  "is_false_positive": true/false,
  "confidence": 0.0-1.0,
  "category": "真实威胁/误报/不确定",
  "summary": "简要分析",
  "recommendation": "处置建议"
}
`

// ChainAnalysisPrompt is the prompt template for analyzing attack chains
const ChainAnalysisPrompt = `你是一个安全分析师。请分析以下攻击链，判断是否为APT攻击。

告警列表：
%s

请输出JSON格式：
{
  "attack_type": "APT/普通攻击/误报",
  "confidence": 0.0-1.0,
  "attack_stage": "侦察/武器化/投递/利用/持久化/命令控制/目标达成",
  "summary": "攻击概述",
  "recommendation": "处置建议"
}
`

// SeverityLevel converts severity code to human-readable string
func SeverityLevel(severity uint8) string {
	switch severity {
	case model.SeverityCritical:
		return "严重"
	case model.SeverityHigh:
		return "高危"
	case model.SeverityMedium:
		return "中危"
	case model.SeverityLow:
		return "低危"
	default:
		return "未知"
	}
}
