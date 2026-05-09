package mapping

// ATT&CK 战术列表
type Tactic string

const (
    TacticReconnaissance   Tactic = "reconnaissance"           // 侦察
    TacticResourceDev      Tactic = "resource-development"    // 资源开发
    TacticInitialAccess    Tactic = "initial-access"          // 初始访问
    TacticExecution        Tactic = "execution"               // 执行
    TacticPersistence      Tactic = "persistence"             // 持久化
    TacticPrivilegeEscal   Tactic = "privilege-escalation"    // 权限提升
    TacticDefenseEvasion    Tactic = "defense-evasion"        // 防御逃避
    TacticCredentialAccess  Tactic = "credential-access"      // 凭证访问
    TacticDiscovery        Tactic = "discovery"               // 发现
    TacticLateralMovement  Tactic = "lateral-movement"        // 横向移动
    TacticCollection        Tactic = "collection"             // 收集
    TacticC2               Tactic = "command-and-control"     // 命令与控制
    TacticExfiltration     Tactic = "exfiltration"            // 数据泄露
    TacticImpact           Tactic = "impact"                 // 影响
)

// TacticOrder 定义战术在攻击链中的顺序
var TacticOrder = map[Tactic]int{
    TacticReconnaissance:   1,
    TacticResourceDev:      2,
    TacticInitialAccess:    3,
    TacticExecution:        4,
    TacticPersistence:     5,
    TacticPrivilegeEscal:   6,
    TacticDefenseEvasion:   7,
    TacticCredentialAccess: 8,
    TacticDiscovery:        9,
    TacticLateralMovement: 10,
    TacticCollection:      11,
    TacticC2:             12,
    TacticExfiltration:   13,
    TacticImpact:         14,
}

// GetTacticName 返回战术的中文名称
func GetTacticName(t Tactic) string {
    names := map[Tactic]string{
        TacticReconnaissance:   "侦察",
        TacticResourceDev:      "资源开发",
        TacticInitialAccess:    "初始访问",
        TacticExecution:        "执行",
        TacticPersistence:      "持久化",
        TacticPrivilegeEscal:   "权限提升",
        TacticDefenseEvasion:    "防御逃避",
        TacticCredentialAccess:  "凭证访问",
        TacticDiscovery:        "发现",
        TacticLateralMovement:  "横向移动",
        TacticCollection:       "收集",
        TacticC2:              "命令与控制",
        TacticExfiltration:    "数据泄露",
        TacticImpact:          "影响",
    }
    return names[t]
}