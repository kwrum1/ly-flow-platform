package rules

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type RuleEngine struct {
	rules    []*models.Rule
	bySID    map[int][]*models.Rule
	counters sync.Map
	mu       sync.RWMutex
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules: make([]*models.Rule, 0),
		bySID: make(map[int][]*models.Rule),
	}
}

func (e *RuleEngine) LoadRules(rules []models.Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = make([]*models.Rule, 0, len(rules))
	e.bySID = make(map[int][]*models.Rule)

	for i := range rules {
		rule := &rules[i]
		if rule.Enabled {
			e.rules = append(e.rules, rule)
			if rule.IfSID > 0 {
				e.bySID[rule.IfSID] = append(e.bySID[rule.IfSID], rule)
			}
		}
	}

	log.Printf("[XDR] 加载规则 %d 条 (启用 %d 条)", len(rules), len(e.rules))
}

func (e *RuleEngine) Match(log *models.NormalizedLog) []*models.MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []*models.MatchResult
	matchedIDs := map[int]bool{}

	for _, rule := range e.rules {
		if rule.IfSID > 0 {
			continue
		}
		if matched, _ := rule.Evaluate(log); matched {
			matchedIDs[rule.ID] = true
			result := &models.MatchResult{
				Rule:      rule,
				Log:       log,
				MatchTime: time.Now(),
			}

			if rule.Frequency > 0 {
				if !e.checkFrequency(rule, log) {
					continue
				}
				result.Rule.Frequency = e.getFrequencyCount(rule, log)
			}

			results = append(results, result)
		}
	}

	for _, rule := range e.rules {
		if rule.IfSID <= 0 || !matchedIDs[rule.IfSID] {
			continue
		}
		if matched, _ := rule.Evaluate(log); matched {
			result := &models.MatchResult{Rule: rule, Log: log, MatchTime: time.Now()}
			if rule.Frequency > 0 {
				if !e.checkFrequency(rule, log) {
					continue
				}
				result.Rule.Frequency = e.getFrequencyCount(rule, log)
			}
			results = append(results, result)
		}
	}

	return results
}

func (e *RuleEngine) checkFrequency(rule *models.Rule, log *models.NormalizedLog) bool {
	if rule.Frequency == 0 {
		return true
	}

	key := e.getCounterKey(rule, log)
	count, ok := e.counters.Load(key)
	if !ok {
		e.counters.Store(key, 1)
		e.scheduleCounterReset(key, rule.Timeframe)
		return false
	}

	countInt := count.(int)
	if countInt >= rule.Frequency {
		return true
	}

	e.counters.Store(key, countInt+1)
	return false
}

func (e *RuleEngine) getFrequencyCount(rule *models.Rule, log *models.NormalizedLog) int {
	key := e.getCounterKey(rule, log)
	count, ok := e.counters.Load(key)
	if !ok {
		return 0
	}
	return count.(int)
}

func (e *RuleEngine) getCounterKey(rule *models.Rule, log *models.NormalizedLog) string {
	key := rule.ID

	if rule.SameSrcip && log.SrcIP != "" {
		key = key*31 + hashString(log.SrcIP)
	}
	if rule.SameUser && log.User != "" {
		key = key*31 + hashString(log.User)
	}

	return fmt.Sprintf("%d", key)
}

func (e *RuleEngine) scheduleCounterReset(key interface{}, timeframe int) {
	go func() {
		time.Sleep(time.Duration(timeframe) * time.Second)
		e.counters.Delete(key)
	}()
}

func hashString(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	return h
}

func (e *RuleEngine) GetRules() []*models.Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules
}

func (e *RuleEngine) GetRulesBySID(sid int) []*models.Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bySID[sid]
}

func (e *RuleEngine) GetStats() *models.RuleStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := &models.RuleStats{
		TotalRules: len(e.rules),
		ByLevel:    make(map[int]int),
		BySource:   make(map[string]int),
		ByGroup:    make(map[string]int),
	}

	for _, rule := range e.rules {
		if rule.Enabled {
			stats.EnabledRules++
		} else {
			stats.DisabledRules++
		}
		stats.ByLevel[rule.Level]++
		stats.BySource[rule.Source]++
		for _, g := range rule.Groups {
			stats.ByGroup[g]++
		}
	}

	return stats
}
