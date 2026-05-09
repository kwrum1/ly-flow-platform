package mapping

import "fmt"

// ATT&CK 技术定义
type Technique struct {
    ID          string   // Txxxx
    Name        string   // 技术名称
    Tactics     []Tactic // 所属战术
    Description string   // 技术描述
    Detection   string   // 检测方法
    Mitigations []string // 缓解措施
}

// TechniqueMap ATT&CK 技术映射表
var TechniqueMap = map[string]*Technique{
    // 命令与控制 (Command and Control)
    "T1071": {
        ID:          "T1071",
        Name:        "Application Layer Protocol",
        Tactics:     []Tactic{TacticC2},
        Description: "攻击者使用应用层协议进行通信",
        Detection:   "检测异常协议流量模式",
    },
    "T1071.004": {
        ID:          "T1071.004",
        Name:        "DNS",
        Tactics:     []Tactic{TacticC2},
        Description: "使用 DNS 协议进行命令与控制",
        Detection:   "监控异常 DNS 查询",
    },
    "T1102": {
        ID:          "T1102",
        Name:        "Web Service",
        Tactics:     []Tactic{TacticC2},
        Description: "使用合法 Web 服务进行命令与控制",
        Detection:   "检测与外部 Web 服务的异常通信",
    },
    "T1102.002": {
        ID:          "T1102.002",
        Name:        "Bidirectional Communication",
        Tactics:     []Tactic{TacticC2},
        Description: "使用双向通信的 Web 服务",
        Detection:   "监控与外部服务的双向通信",
    },

    // 执行 (Execution)
    "T1059": {
        ID:          "T1059",
        Name:        "Command and Scripting Interpreter",
        Tactics:     []Tactic{TacticExecution},
        Description: "使用命令和脚本解释器执行命令",
        Detection:   "监控异常命令执行",
    },
    "T1059.001": {
        ID:          "T1059.001",
        Name:        "PowerShell",
        Tactics:     []Tactic{TacticExecution, TacticDefenseEvasion, TacticPersistence},
        Description: "使用 PowerShell 执行命令",
        Detection:   "监控 PowerShell 执行",
    },
    "T1059.003": {
        ID:          "T1059.003",
        Name:        "Windows Command Shell",
        Tactics:     []Tactic{TacticExecution},
        Description: "使用 Windows 命令 shell 执行命令",
        Detection:   "监控可疑命令行",
    },
    "T1059.004": {
        ID:          "T1059.004",
        Name:        "Unix Shell",
        Tactics:     []Tactic{TacticExecution},
        Description: "使用 Unix shell 执行命令",
        Detection:   "监控可疑 shell 命令",
    },

    // 数据泄露 (Exfiltration)
    "T1048": {
        ID:          "T1048",
        Name:        "Exfiltration Over Alternative Protocol",
        Tactics:     []Tactic{TacticExfiltration},
        Description: "使用替代协议进行数据泄露",
        Detection:   "监控异常出站流量",
    },
    "T1048.003": {
        ID:          "T1048.003",
        Name:        "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
        Tactics:     []Tactic{TacticExfiltration},
        Description: "通过非 C2 协议加密或混淆后泄露数据",
        Detection:   "监控加密的异常流量",
    },

    // 初始访问 (Initial Access)
    "T1566": {
        ID:          "T1566",
        Name:        "Phishing",
        Tactics:     []Tactic{TacticInitialAccess},
        Description: "网络钓鱼攻击",
        Detection:   "检测钓鱼邮件和链接",
    },
    "T1566.001": {
        ID:          "T1566.001",
        Name:        "Malicious Attachment",
        Tactics:     []Tactic{TacticInitialAccess},
        Description: "通过恶意附件进行钓鱼攻击",
        Detection:   "检测邮件附件",
    },
    "T1566.002": {
        ID:          "T1566.002",
        Name:        "Malicious Link",
        Tactics:     []Tactic{TacticInitialAccess},
        Description: "通过恶意链接进行钓鱼攻击",
        Detection:   "检测钓鱼链接",
    },

    // 影响 (Impact)
    "T1486": {
        ID:          "T1486",
        Name:        "Data Encrypted for Impact",
        Tactics:     []Tactic{TacticImpact},
        Description: "加密数据以造成影响（勒索软件）",
        Detection:   "检测文件加密行为",
    },
    "T1490": {
        ID:          "T1490",
        Name:        "Inhibit System Recovery",
        Tactics:     []Tactic{TacticImpact},
        Description: "阻止系统恢复（删除备份）",
        Detection:   "监控备份删除行为",
    },
    "T1489": {
        ID:          "T1489",
        Name:        "Service Stop",
        Tactics:     []Tactic{TacticImpact},
        Description: "停止服务以造成影响",
        Detection:   "监控服务停止行为",
    },

    // 持久化 (Persistence)
    "T1543": {
        ID:          "T1543",
        Name:        "Create/Modify System Process",
        Tactics:     []Tactic{TacticPersistence, TacticPrivilegeEscal},
        Description: "创建或修改系统进程",
        Detection:   "监控异常进程创建",
    },
    "T1547": {
        ID:          "T1547",
        Name:        "Boot or Logon Autostart Execution",
        Tactics:     []Tactic{TacticPersistence, TacticPrivilegeEscal},
        Description: "通过启动或登录自动执行",
        Detection:   "监控启动项变化",
    },

    // 凭证访问 (Credential Access)
    "T1110": {
        ID:          "T1110",
        Name:        "Brute Force",
        Tactics:     []Tactic{TacticCredentialAccess},
        Description: "暴力破解凭证",
        Detection:   "监控异常登录失败",
    },
    "T1003": {
        ID:          "T1003",
        Name:        "OS Credential Dumping",
        Tactics:     []Tactic{TacticCredentialAccess},
        Description: "操作系统凭证转储",
        Detection:   "监控敏感进程内存访问",
    },

    // 防御逃避 (Defense Evasion)
    "T1562": {
        ID:          "T1562",
        Name:        "Impair Defenses",
        Tactics:     []Tactic{TacticDefenseEvasion},
        Description: "削弱防御措施",
        Detection:   "监控安全工具操作",
    },
    "T1070": {
        ID:          "T1070",
        Name:        "Indicator Removal on Host",
        Tactics:     []Tactic{TacticDefenseEvasion},
        Description: "清除主机上的指标",
        Detection:   "监控日志删除行为",
    },

    // 发现 (Discovery)
    "T1046": {
        ID:          "T1046",
        Name:        "Network Service Discovery",
        Tactics:     []Tactic{TacticDiscovery},
        Description: "网络服务发现",
        Detection:   "监控网络扫描行为",
    },
    "T1082": {
        ID:          "T1082",
        Name:        "System Information Discovery",
        Tactics:     []Tactic{TacticDiscovery},
        Description: "系统信息发现",
        Detection:   "监控系统信息收集",
    },

    // 横向移动 (Lateral Movement)
    "T1021": {
        ID:          "T1021",
        Name:        "Remote Services",
        Tactics:     []Tactic{TacticLateralMovement},
        Description: "使用远程服务进行横向移动",
        Detection:   "监控远程连接",
    },

    // 收集 (Collection)
    "T1560": {
        ID:          "T1560",
        Name:        "Archive Collected Data",
        Tactics:     []Tactic{TacticCollection},
        Description: "归档收集的数据",
        Detection:   "监控压缩和加密行为",
    },
}

// GetTechnique 返回指定 ID 的技术
func GetTechnique(id string) *Technique {
    return TechniqueMap[id]
}

// GetTechniquesByTactic 返回指定战术的所有技术
func GetTechniquesByTactic(tactic Tactic) []*Technique {
    var techniques []*Technique
    for _, tech := range TechniqueMap {
        for _, t := range tech.Tactics {
            if t == tactic {
                techniques = append(techniques, tech)
                break
            }
        }
    }
    return techniques
}

// FormatTechniqueID 格式化技术 ID
func FormatTechniqueID(tacticID, subID string) string {
    if subID != "" {
        return fmt.Sprintf("%s.%s", tacticID, subID)
    }
    return tacticID
}