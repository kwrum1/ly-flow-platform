package mapping

import (
	"fmt"
	"sort"
	"time"

	"ly-flow-platform/pkg/model"
)

// AttackStep 攻击步骤
type AttackStep struct {
	ID         string           // 步骤唯一 ID
	Technique  *Technique       // ATT&CK 技术
	Alert      *model.Alert     // 关联的告警
	Timestamp  time.Time        // 时间戳
	Confidence float64          // 置信度 0-1
	Evidence   []string         // 证据列表
	SrcIP      string           // 源 IP
	DstIP      string           // 目标 IP
}

// NewAttackStep 创建攻击步骤
func NewAttackStep(technique *Technique, alert *model.Alert, confidence float64) *AttackStep {
	return &AttackStep{
		ID:         fmt.Sprintf("%s-%d", technique.ID, alert.ID),
		Technique:  technique,
		Alert:      alert,
		Timestamp:  alert.Timestamp,
		Confidence: confidence,
		Evidence:   make([]string, 0),
		SrcIP:      alert.SrcIP,
		DstIP:      alert.DstIP,
	}
}

// AddEvidence 添加证据
func (s *AttackStep) AddEvidence(evidence string) {
	s.Evidence = append(s.Evidence, evidence)
}

// GetTactics 返回该步骤涉及的所有战术
func (s *AttackStep) GetTactics() []Tactic {
	return s.Technique.Tactics
}

// IsHighConfidence 判断是否为高置信度步骤
func (s *AttackStep) IsHighConfidence() bool {
	return s.Confidence >= 0.8
}

// AttackChain 攻击链
type AttackChain struct {
	ID         string        // 攻击链唯一 ID
	Steps      []*AttackStep // 攻击步骤列表
	StartTime  time.Time     // 开始时间
	EndTime    time.Time     // 结束时间
	Status     string        // active/completed/archived
	SrcIP      string        // 攻击源 IP
	DstIPs     []string      // 攻击目标 IP 列表
	TechniqueIDs []string    // 技术 ID 列表（去重）
}

// ChainStatus 常量
const (
	ChainStatusActive    = "active"
	ChainStatusCompleted = "completed"
	ChainStatusArchived  = "archived"
)

// NewAttackChain 创建新的攻击链
func NewAttackChain(id string) *AttackChain {
	now := time.Now()
	return &AttackChain{
		ID:        id,
		Steps:     make([]*AttackStep, 0),
		StartTime: now,
		EndTime:   now,
		Status:    ChainStatusActive,
		SrcIP:     "",
		DstIPs:    make([]string, 0),
		TechniqueIDs: make([]string, 0),
	}
}

// Add 添加攻击步骤
func (c *AttackChain) Add(step *AttackStep) {
	// 去重检查
	for _, s := range c.Steps {
		if s.ID == step.ID {
			return
		}
	}

	c.Steps = append(c.Steps, step)
	c.updateTimes()
	c.updateIPs()
	c.updateTechniqueIDs()
}

// updateTimes 更新时间
func (c *AttackChain) updateTimes() {
	if len(c.Steps) == 0 {
		return
	}

	sort.Slice(c.Steps, func(i, j int) bool {
		return c.Steps[i].Timestamp.Before(c.Steps[j].Timestamp)
	})

	c.StartTime = c.Steps[0].Timestamp
	c.EndTime = c.Steps[len(c.Steps)-1].Timestamp
}

// updateIPs 更新 IP 列表
func (c *AttackChain) updateIPs() {
	srcIPs := make(map[string]bool)
	dstIPs := make(map[string]bool)

	for _, step := range c.Steps {
		if step.SrcIP != "" {
			srcIPs[step.SrcIP] = true
		}
		if step.DstIP != "" {
			dstIPs[step.DstIP] = true
		}
	}

	if len(srcIPs) > 0 {
		for ip := range srcIPs {
			c.SrcIP = ip
			break
		}
	}

	c.DstIPs = make([]string, 0, len(dstIPs))
	for ip := range dstIPs {
		c.DstIPs = append(c.DstIPs, ip)
	}
}

// updateTechniqueIDs 更新技术 ID 列表
func (c *AttackChain) updateTechniqueIDs() {
	techIDs := make(map[string]bool)
	for _, step := range c.Steps {
		if step.Technique != nil {
			techIDs[step.Technique.ID] = true
		}
	}

	c.TechniqueIDs = make([]string, 0, len(techIDs))
	for id := range techIDs {
		c.TechniqueIDs = append(c.TechniqueIDs, id)
	}
	sort.Strings(c.TechniqueIDs)
}

// GetTactics 返回攻击链涉及的所有战术
func (c *AttackChain) GetTactics() []Tactic {
	tacticSet := make(map[Tactic]bool)
	for _, step := range c.Steps {
		for _, t := range step.GetTactics() {
			tacticSet[t] = true
		}
	}

	tactics := make([]Tactic, 0, len(tacticSet))
	for t := range tacticSet {
		tactics = append(tactics, t)
	}

	// 按战术顺序排序
	sort.Slice(tactics, func(i, j int) bool {
		return TacticOrder[tactics[i]] < TacticOrder[tactics[j]]
	})

	return tactics
}

// GetTechniques 返回攻击链涉及的所有技术 ID
func (c *AttackChain) GetTechniques() []string {
	return c.TechniqueIDs
}

// GetTechniqueCount 返回技术种类数
func (c *AttackChain) GetTechniqueCount() int {
	return len(c.TechniqueIDs)
}

// GetStepCount 返回步骤数
func (c *AttackChain) GetStepCount() int {
	return len(c.Steps)
}

// GetDuration 返回攻击持续时间
func (c *AttackChain) GetDuration() time.Duration {
	return c.EndTime.Sub(c.StartTime)
}

// GetRiskScore 计算风险评分
func (c *AttackChain) GetRiskScore() int {
	if len(c.Steps) == 0 {
		return 0
	}

	// 基于战术数量和技术数量计算
	tacticCount := len(c.GetTactics())
	techCount := c.GetTechniqueCount()

	// 基础分：战术覆盖
	score := tacticCount * 10

	// 技术多样性加分
	score += techCount * 5

	// 严重程度加分
	for _, step := range c.Steps {
		if step.Alert != nil {
			switch step.Alert.Severity {
			case model.SeverityCritical:
				score += 20
			case model.SeverityHigh:
				score += 15
			case model.SeverityMedium:
				score += 10
			case model.SeverityLow:
				score += 5
			}
		}
	}

	// 置信度加权
	totalConfidence := 0.0
	for _, step := range c.Steps {
		totalConfidence += step.Confidence
	}
	if len(c.Steps) > 0 {
		avgConfidence := totalConfidence / float64(len(c.Steps))
		score = int(float64(score) * (0.5 + avgConfidence*0.5))
	}

	// 上限 100
	if score > 100 {
		score = 100
	}

	return score
}

// Complete 标记攻击链为完成
func (c *AttackChain) Complete() {
	c.Status = ChainStatusCompleted
}

// Archive 归档攻击链
func (c *AttackChain) Archive() {
	c.Status = ChainStatusArchived
}

// ContainsTechnique 检查是否包含指定技术
func (c *AttackChain) ContainsTechnique(techniqueID string) bool {
	for _, id := range c.TechniqueIDs {
		if id == techniqueID {
			return true
		}
	}
	return false
}

// ContainsTactic 检查是否包含指定战术
func (c *AttackChain) ContainsTactic(tactic Tactic) bool {
	for _, step := range c.Steps {
		for _, t := range step.GetTactics() {
			if t == tactic {
				return true
			}
		}
	}
	return false
}

// GetStepsByTactic 返回指定战术的步骤
func (c *AttackChain) GetStepsByTactic(tactic Tactic) []*AttackStep {
	var steps []*AttackStep
	for _, step := range c.Steps {
		for _, t := range step.GetTactics() {
			if t == tactic {
				steps = append(steps, step)
				break
			}
		}
	}
	return steps
}

// GetHighConfidenceSteps 返回高置信度步骤
func (c *AttackChain) GetHighConfidenceSteps() []*AttackStep {
	var steps []*AttackStep
	for _, step := range c.Steps {
		if step.IsHighConfidence() {
			steps = append(steps, step)
		}
	}
	return steps
}