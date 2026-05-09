package mapping

// GetDefaultRules 返回默认映射规则
func GetDefaultRules() []MappingRule {
	return []MappingRule{
		// ==================== 挖矿相关 ====================
		// 挖矿域名 -> 阻止系统恢复（影响）
		{
			Category:     "mining",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1490",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},
		{
			Category:     "mining",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1490",
			Confidence:   0.95,
			ExtractFunc:  nil,
		},

		// ==================== DNS 相关 ====================
		// DNS Tunnel -> DNS 命令与控制
		{
			Category:     "dns_tunnel",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1071",
			SubTechniqueID: "T1071.004",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},
		{
			Category:     "dns_tunnel",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1071",
			SubTechniqueID: "T1071.004",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},

		// DGA -> Web 服务（隐蔽通信）
		{
			Category:     "dga",
			Severity:     "medium",
			Signature:    "",
			TechniqueID:  "T1102",
			SubTechniqueID: "T1102.002",
			Confidence:   0.75,
			ExtractFunc:  nil,
		},
		{
			Category:     "dga",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1102",
			SubTechniqueID: "T1102.002",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},

		// ==================== 欺诈相关 ====================
		// 涉诈 -> 网络钓鱼
		{
			Category:     "fraud",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1566",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},
		{
			Category:     "fraud",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1566",
			SubTechniqueID: "T1566.001",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},

		// ==================== 注入攻击 ====================
		// SQL 注入 -> 命令执行
		{
			Category:     "sql_injection",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},
		{
			Category:     "sql_injection",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},

		// XSS -> 命令执行
		{
			Category:     "xss",
			Severity:     "medium",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.7,
			ExtractFunc:  nil,
		},

		// ==================== Webshell ====================
		// Webshell -> PowerShell 命令执行
		{
			Category:     "webshell",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1059",
			SubTechniqueID: "T1059.001",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},
		{
			Category:     "webshell",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1059",
			SubTechniqueID: "T1059.001",
			Confidence:   0.95,
			ExtractFunc:  nil,
		},

		// ==================== 后门 ====================
		// 后门 -> 命令执行
		{
			Category:     "backdoor",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},

		// ==================== 勒索软件 ====================
		// 勒索软件 -> 数据加密
		{
			Category:     "ransomware",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1486",
			Confidence:   0.95,
			ExtractFunc:  nil,
		},

		// ==================== 暴力破解 ====================
		// 暴力破解 -> 凭证暴力破解
		{
			Category:     "bruteforce",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1110",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},
		{
			Category:     "bruteforce",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1110",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},

		// ==================== 可疑活动 ====================
		// 可疑 -> 命令执行
		{
			Category:     "suspicious",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.7,
			ExtractFunc:  nil,
		},
		{
			Category:     "suspicious",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.8,
			ExtractFunc:  nil,
		},

		// ==================== 恶意软件 ====================
		// 恶意软件 -> 命令执行
		{
			Category:     "malware",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},
		{
			Category:     "malware",
			Severity:     "critical",
			Signature:    "",
			TechniqueID:  "T1059",
			Confidence:   0.9,
			ExtractFunc:  nil,
		},

		// ==================== 数据泄露 ====================
		// 大量外传 -> 替代协议数据泄露
		{
			Category:     "data_exfiltration",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1048",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},

		// ==================== 持久化 ====================
		// 提权 -> 持久化
		{
			Category:     "privilege_escalation",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1543",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},

		// ==================== 凭证访问 ====================
		// 凭证窃取 -> 凭证访问
		{
			Category:     "credential_theft",
			Severity:     "high",
			Signature:    "",
			TechniqueID:  "T1003",
			Confidence:   0.85,
			ExtractFunc:  nil,
		},
	}
}

// CategoryMappingRule 类别到技术的默认映射
var CategoryMappingRule = map[string]struct {
	TechniqueID     string
	SubTechniqueID  string
	DefaultSeverity string
}{
	"mining":            {TechniqueID: "T1490", DefaultSeverity: "high"},
	"dns_tunnel":        {TechniqueID: "T1071", SubTechniqueID: "T1071.004", DefaultSeverity: "high"},
	"dga":               {TechniqueID: "T1102", SubTechniqueID: "T1102.002", DefaultSeverity: "medium"},
	"fraud":             {TechniqueID: "T1566", DefaultSeverity: "high"},
	"sql_injection":     {TechniqueID: "T1059", DefaultSeverity: "high"},
	"xss":               {TechniqueID: "T1059", DefaultSeverity: "medium"},
	"webshell":          {TechniqueID: "T1059", SubTechniqueID: "T1059.001", DefaultSeverity: "high"},
	"backdoor":          {TechniqueID: "T1059", DefaultSeverity: "high"},
	"ransomware":        {TechniqueID: "T1486", DefaultSeverity: "critical"},
	"bruteforce":        {TechniqueID: "T1110", DefaultSeverity: "high"},
	"suspicious":        {TechniqueID: "T1059", DefaultSeverity: "medium"},
	"malware":           {TechniqueID: "T1059", DefaultSeverity: "high"},
	"data_exfiltration": {TechniqueID: "T1048", DefaultSeverity: "high"},
}

// GetRuleByCategory 根据类别获取映射规则
func GetRuleByCategory(category string) *MappingRule {
	ruleDef, ok := CategoryMappingRule[category]
	if !ok {
		return nil
	}

	confidence := 0.7
	switch ruleDef.DefaultSeverity {
	case "critical":
		confidence = 0.9
	case "high":
		confidence = 0.85
	case "medium":
		confidence = 0.75
	case "low":
		confidence = 0.6
	}

	return &MappingRule{
		Category:        category,
		TechniqueID:     ruleDef.TechniqueID,
		SubTechniqueID:  ruleDef.SubTechniqueID,
		Confidence:      confidence,
	}
}