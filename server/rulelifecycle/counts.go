package rulelifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

func (m *Manager) ActiveRuleCounts(_ context.Context) (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	manifest, _, err := m.loadActive()
	if err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(manifest.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("read active rule bundle: %w", err)
	}
	var bundle struct {
		Rules []struct {
			Category string `json:"category"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(contents, &bundle); err != nil {
		return nil, fmt.Errorf("decode active rule bundle: %w", err)
	}
	counts := map[string]int{}
	for _, rule := range bundle.Rules {
		counts[rule.Category]++
	}
	return counts, nil
}
