package aggregator

import (
	"sync"
	"time"
	"ly-flow-platform/pkg/model"
)

type Aggregator struct {
	window    time.Duration      // 时间窗口
	threshold float64            // 相似度阈值
	groups    map[string]*AlertGroup
	mu        sync.RWMutex
}

type AlertGroup struct {
	Key      string
	Primary  *model.Alert
	Count    int
	LastSeen time.Time
	Sources  []string
}

func NewAggregator(window time.Duration, threshold float64) *Aggregator {
	return &Aggregator{
		window:    window,
		threshold: threshold,
		groups:    make(map[string]*AlertGroup),
	}
}

// Add 添加告警到聚合器
func (a *Aggregator) Add(alert *model.Alert) *AlertGroup {
	fingerprint := AlertFingerprint(alert)

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	key := fingerprint

	// 尝试查找现有分组
	if group, exists := a.groups[key]; exists {
		// 检查时间窗口
		if now.Sub(group.LastSeen) <= a.window {
			group.Count++
			group.LastSeen = now
			// 添加新的来源
			if !contains(group.Sources, alert.SensorID) {
				group.Sources = append(group.Sources, alert.SensorID)
			}
			return group
		}
	}

	// 创建新分组
	group := &AlertGroup{
		Key:      key,
		Primary:  alert,
		Count:    1,
		LastSeen: now,
		Sources:  []string{alert.SensorID},
	}
	a.groups[key] = group

	return group
}

// GetGroups 返回所有告警分组
func (a *Aggregator) GetGroups() []*AlertGroup {
	a.mu.RLock()
	defer a.mu.RUnlock()

	groups := make([]*AlertGroup, 0, len(a.groups))
	for _, group := range a.groups {
		groups = append(groups, group)
	}
	return groups
}

// Cleanup 清理过期的告警分组
func (a *Aggregator) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for key, group := range a.groups {
		if now.Sub(group.LastSeen) > a.window {
			delete(a.groups, key)
		}
	}
}

// GetGroupCount 返回当前分组数量
func (a *Aggregator) GetGroupCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.groups)
}

// contains 检查切片是否包含指定元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
