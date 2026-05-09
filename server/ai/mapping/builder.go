package mapping

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"ly-flow-platform/pkg/model"
)

// Builder 攻击链构建器
type Builder struct {
	chains map[string]*AttackChain   // 活跃的攻击链
	mapper *Mapper                   // 告警映射器
	window time.Duration             // 时间窗口
	mu     sync.RWMutex              // 读写锁
}

// BuilderConfig 构建器配置
type BuilderConfig struct {
	WindowDuration     time.Duration // 时间窗口，默认 10 分钟
	MaxChains          int           // 最大活跃链数，默认 1000
	ChainTimeout       time.Duration // 链超时时间，默认 1 小时
}

// DefaultBuilderConfig 返回默认配置
func DefaultBuilderConfig() *BuilderConfig {
	return &BuilderConfig{
		WindowDuration: 10 * time.Minute,
		MaxChains:     1000,
		ChainTimeout:  1 * time.Hour,
	}
}

// NewBuilder 创建新的攻击链构建器
func NewBuilder(window time.Duration) *Builder {
	return &Builder{
		chains: make(map[string]*AttackChain),
		mapper: NewMapper(),
		window: window,
	}
}

// NewBuilderWithConfig 使用配置创建构建器
func NewBuilderWithConfig(cfg *BuilderConfig) *Builder {
	if cfg == nil {
		cfg = DefaultBuilderConfig()
	}

	b := &Builder{
		chains: make(map[string]*AttackChain, cfg.MaxChains),
		mapper: NewMapper(),
		window: cfg.WindowDuration,
	}

	// 启动清理 goroutine
	go b.cleanupLoop(cfg.ChainTimeout)

	return b
}

// Process 处理告警，返回关联的攻击链
func (b *Builder) Process(alert *model.Alert) *AttackChain {
	if alert == nil {
		return nil
	}

	// 映射告警到 ATT&CK 技术
	step := b.mapper.Map(alert)
	if step == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// 尝试找到关联的攻击链
	chainID := b.findOrCreateChain(alert, step)

	// 获取攻击链
	chain, ok := b.chains[chainID]
	if !ok {
		return nil
	}

	// 添加步骤
	chain.Add(step)

	return chain
}

// findOrCreateChain 查找或创建攻击链
func (b *Builder) findOrCreateChain(alert *model.Alert, step *AttackStep) string {
	// 基于源 IP 和目标 IP 尝试关联
	for _, chain := range b.chains {
		// 检查时间窗口内是否有相似告警
		if b.isRelated(chain, alert, step) {
			return chain.ID
		}
	}

	// 创建新链
	chainID := b.generateChainID(alert)
	chain := NewAttackChain(chainID)
	chain.Add(step)

	b.chains[chainID] = chain

	return chainID
}

// isRelated 检查告警是否与现有链相关
func (b *Builder) isRelated(chain *AttackChain, alert *model.Alert, step *AttackStep) bool {
	now := time.Now()

	// 检查时间窗口
	if chain.EndTime.Before(now.Add(-b.window)) {
		return false
	}

	// 检查源 IP 关联
	if chain.SrcIP != "" && chain.SrcIP == alert.SrcIP {
		return true
	}

	// 检查目标 IP 关联
	if len(chain.DstIPs) > 0 {
		for _, ip := range chain.DstIPs {
			if ip == alert.DstIP {
				return true
			}
		}
	}

	// 检查技术关联（相同技术的连续告警）
	if step != nil && step.Technique != nil {
		if chain.ContainsTechnique(step.Technique.ID) {
			return true
		}
	}

	// 检查战术关联
	if chain.ContainsTactic(step.Technique.Tactics[0]) {
		return true
	}

	return false
}

// generateChainID 生成链 ID
func (b *Builder) generateChainID(alert *model.Alert) string {
	data := fmt.Sprintf("%s-%s-%s-%d",
		alert.SrcIP,
		alert.DstIP,
		alert.Category,
		alert.Timestamp.Unix())

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("chain-%s", hex.EncodeToString(hash[:8]))
}

// GetActiveChains 返回所有活跃攻击链
func (b *Builder) GetActiveChains() []*AttackChain {
	b.mu.RLock()
	defer b.mu.RUnlock()

	chains := make([]*AttackChain, 0, len(b.chains))
	for _, chain := range b.chains {
		if chain.Status == ChainStatusActive {
			chains = append(chains, chain)
		}
	}
	return chains
}

// GetChain 返回指定 ID 的攻击链
func (b *Builder) GetChain(id string) *AttackChain {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.chains[id]
}

// CompleteChain 标记攻击链为完成
func (b *Builder) CompleteChain(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if chain, ok := b.chains[id]; ok {
		chain.Complete()
	}
}

// ArchiveChain 归档攻击链
func (b *Builder) ArchiveChain(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if chain, ok := b.chains[id]; ok {
		chain.Archive()
	}
}

// cleanupLoop 定期清理超时链
func (b *Builder) cleanupLoop(timeout time.Duration) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		b.cleanup(timeout)
	}
}

// cleanup 清理超时链
func (b *Builder) cleanup(timeout time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for id, chain := range b.chains {
		if chain.EndTime.Before(now.Add(-timeout)) {
			chain.Complete()
			delete(b.chains, id)
		}
	}
}

// GetMapper 返回映射器
func (b *Builder) GetMapper() *Mapper {
	return b.mapper
}

// SetMapper 设置映射器
func (b *Builder) SetMapper(mapper *Mapper) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mapper = mapper
}

// ChainStats 攻击链统计
type ChainStats struct {
	TotalChains     int
	ActiveChains    int
	CompletedChains int
	ArchivedChains   int
	TotalSteps      int
	AvgStepsPerChain float64
}

// GetStats 返回构建器统计信息
func (b *Builder) GetStats() *ChainStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := &ChainStats{
		TotalChains: len(b.chains),
	}

	var totalSteps int
	for _, chain := range b.chains {
		switch chain.Status {
		case ChainStatusActive:
			stats.ActiveChains++
		case ChainStatusCompleted:
			stats.CompletedChains++
		case ChainStatusArchived:
			stats.ArchivedChains++
		}
		totalSteps += len(chain.Steps)
	}

	stats.TotalSteps = totalSteps
	if stats.TotalChains > 0 {
		stats.AvgStepsPerChain = float64(totalSteps) / float64(stats.TotalChains)
	}

	return stats
}