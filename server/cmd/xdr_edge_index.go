package main

import (
	"sort"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

// edgeIndexConfig bounds candidate generation. Correlation used to compare every
// event with every other event (O(n^2)); the index only compares events that
// share an entity or a lateral-movement stage inside the time window.
type edgeIndexConfig struct {
	Window    time.Duration
	MaxPerKey int
}

func defaultEdgeIndexConfig() edgeIndexConfig {
	return edgeIndexConfig{Window: 2 * time.Hour, MaxPerKey: 256}
}

// indexedEdgePairs returns unique (i,j) pairs, i<j, that share at least one
// correlation key and are within the time window. It also reports how many
// buckets were truncated, so callers can mark the run as partially correlated
// instead of silently dropping candidates.
func indexedEdgePairs(events []*models.CanonicalEventV2, cfg edgeIndexConfig) ([][2]int, int) {
	if len(events) < 2 {
		return nil, 0
	}
	if cfg.Window <= 0 {
		cfg.Window = 2 * time.Hour
	}
	if cfg.MaxPerKey <= 0 {
		cfg.MaxPerKey = 256
	}

	byHost := map[string][]int{}
	byIdentity := map[string][]int{}
	bySrcIP := map[string][]int{}
	byVictim := map[string][]int{}
	byStage := map[string][]int{}

	add := func(index map[string][]int, key string, position int) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		index[key] = append(index[key], position)
	}

	lateralStages := map[string]bool{
		strings.ToLower(models.StageCredentialAccess):   true,
		strings.ToLower(models.StageLateralMovement):    true,
		strings.ToLower(models.StageExecution):          true,
	}

	for position, event := range events {
		if event == nil {
			continue
		}
		add(byHost, event.AgentID, position)
		add(byIdentity, event.ActorIdentity, position)
		add(bySrcIP, event.NormalizedSrcIP, position)
		add(byVictim, event.VictimAsset, position)
		if stage := strings.ToLower(strings.TrimSpace(event.StageHint)); lateralStages[stage] {
			byStage[stage] = append(byStage[stage], position)
		}
	}

	seen := make(map[[2]int]struct{}, len(events)*2)
	pairs := make([][2]int, 0, len(events)*2)
	truncated := 0

	collect := func(bucket []int, windowed bool) {
		if len(bucket) < 2 {
			return
		}
		if len(bucket) > cfg.MaxPerKey {
			truncated++
			bucket = bucket[len(bucket)-cfg.MaxPerKey:]
		}
		for a := 0; a < len(bucket); a++ {
			for b := a + 1; b < len(bucket); b++ {
				left, right := bucket[a], bucket[b]
				if left == right {
					continue
				}
				if left > right {
					left, right = right, left
				}
				// same-process / same-identity / weak-IP edges carry no time
				// bound in classifyEdge, so the index must not impose one.
				if windowed && !withinEdgeWindow(events[left], events[right], cfg.Window) {
					continue
				}
				key := [2]int{left, right}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				pairs = append(pairs, key)
			}
		}
	}

	for _, bucket := range byHost {
		collect(bucket, false)
	}
	for _, bucket := range byIdentity {
		collect(bucket, false)
	}
	for _, bucket := range bySrcIP {
		collect(bucket, false)
	}
	for _, bucket := range byVictim {
		collect(bucket, true)
	}

	// Lateral movement can be inferred from stage progression even without a
	// shared host or identity, so pair the relevant stage buckets explicitly.
	collectAcross := func(leftKey, rightKey string) {
		left, right := byStage[leftKey], byStage[rightKey]
		if len(left) == 0 || len(right) == 0 {
			return
		}
		if len(left) > cfg.MaxPerKey || len(right) > cfg.MaxPerKey {
			truncated++
		}
		for _, i := range left {
			for _, j := range right {
				if i == j {
					continue
				}
				a, b := i, j
				if a > b {
					a, b = b, a
				}
				key := [2]int{a, b}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				pairs = append(pairs, key)
			}
		}
	}
	collectAcross(strings.ToLower(models.StageCredentialAccess), strings.ToLower(models.StageLateralMovement))
	collectAcross(strings.ToLower(models.StageLateralMovement), strings.ToLower(models.StageExecution))

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] == pairs[j][0] {
			return pairs[i][1] < pairs[j][1]
		}
		return pairs[i][0] < pairs[j][0]
	})
	return pairs, truncated
}

func withinEdgeWindow(a, b *models.CanonicalEventV2, window time.Duration) bool {
	if a == nil || b == nil {
		return false
	}
	diff := a.ObservedAt.Sub(b.ObservedAt)
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}
