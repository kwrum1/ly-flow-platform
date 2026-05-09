package aggregator

import (
	"time"
)

type Config struct {
	WindowDuration      time.Duration // 时间窗口，默认 5 分钟
	SimilarityThreshold float64       // 相似度阈值，默认 0.85
	MaxGroups           int           // 最大分组数，默认 10000
	CleanupInterval     time.Duration // 清理间隔，默认 1 小时
}

func DefaultConfig() *Config {
	return &Config{
		WindowDuration:      5 * time.Minute,
		SimilarityThreshold: 0.85,
		MaxGroups:           10000,
		CleanupInterval:     1 * time.Hour,
	}
}
