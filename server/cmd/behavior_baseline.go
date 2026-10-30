package main

import (
	"strings"
	"sync"
)

// T1-05 behaviour baseline.
//
// The baseline learns which processes and users normally appear on an entity
// and flags values it has never seen. It runs in shadow mode by default: the
// verdict is attached to the event so analysts can review it, but it never
// raises severity, creates an incident or suppresses anything. Enforce mode is
// opt-in and still only annotates; promotion is a separate, reviewed step.

const (
	behaviorBaselineOff     = "off"
	behaviorBaselineShadow  = "shadow"
	behaviorBaselineEnforce = "enforce"

	// behaviorBaselineMinSupport is how many observations an entity needs
	// before "never seen" means anything. Below it, novelty is unknown.
	behaviorBaselineMinSupport = 20
	// behaviorBaselineMaxValues bounds memory per entity feature.
	behaviorBaselineMaxValues = 512
)

type behaviorSeries struct {
	total  int
	values map[string]int
}

type behaviorBaseline struct {
	mu      sync.Mutex
	series  map[string]*behaviorSeries
	minSeen int
	maxSize int
}

func newBehaviorBaseline() *behaviorBaseline {
	return &behaviorBaseline{
		series:  map[string]*behaviorSeries{},
		minSeen: behaviorBaselineMinSupport,
		maxSize: behaviorBaselineMaxValues,
	}
}

// resolveBehaviorBaselineMode validates the feature flag. Unknown values fall
// back to shadow, never to enforce.
func resolveBehaviorBaselineMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case behaviorBaselineOff:
		return behaviorBaselineOff
	case behaviorBaselineEnforce:
		return behaviorBaselineEnforce
	default:
		return behaviorBaselineShadow
	}
}

type behaviorVerdict struct {
	Mode    string `json:"mode"`
	Entity  string `json:"entity"`
	Feature string `json:"feature"`
	Value   string `json:"value"`
	Novel   bool   `json:"novel"`
	Support int    `json:"support"`
	// WouldAlert is true only when the baseline is mature enough to judge and
	// the value is new. It is advisory in shadow mode.
	WouldAlert bool `json:"would_alert"`
}

// Observe records a value and reports whether it is novel for that entity.
func (b *behaviorBaseline) Observe(entity, feature, value string) behaviorVerdict {
	entity = strings.TrimSpace(entity)
	feature = strings.TrimSpace(feature)
	value = strings.TrimSpace(value)
	verdict := behaviorVerdict{Entity: entity, Feature: feature, Value: value}
	if entity == "" || feature == "" || value == "" {
		return verdict
	}

	key := entity + "\x00" + feature
	b.mu.Lock()
	series, ok := b.series[key]
	if !ok {
		series = &behaviorSeries{values: map[string]int{}}
		b.series[key] = series
	}
	_, seen := series.values[value]
	verdict.Novel = !seen
	verdict.Support = series.total
	verdict.WouldAlert = verdict.Novel && series.total >= b.minSeen

	if !seen && len(series.values) >= b.maxSize {
		// Bound memory: once the value set is full, stop learning new values
		// and mark the series as saturated instead of evicting evidence.
		verdict.WouldAlert = false
		verdict.Feature = feature + ":saturated"
		b.mu.Unlock()
		return verdict
	}
	series.values[value]++
	series.total++
	b.mu.Unlock()
	return verdict
}

// annotateBehaviorBaseline attaches the shadow verdict to an XDR event.
// Missing entity/feature values are left absent: the event is not judged.
func annotateBehaviorBaseline(event map[string]interface{}, baseline *behaviorBaseline, mode string) {
	if event == nil || baseline == nil || mode == behaviorBaselineOff {
		return
	}
	entity := firstNonEmpty(
		xdrPickString(event, "agent_id"),
		xdrPickString(event, "hostname"),
		xdrPickString(event, "entities.hostname"),
		xdrPickString(event, "src_ip"),
	)
	if entity == "" {
		return
	}
	process := firstNonEmpty(
		xdrPickString(event, "process_name", "process.name", "process"),
		xdrPickString(event, "command_line", "process.command_line"),
	)
	user := xdrPickString(event, "user", "actor_identity", "entities.user")

	verdicts := []behaviorVerdict{}
	if process != "" {
		verdicts = append(verdicts, baseline.Observe(entity, "process", process))
	}
	if user != "" {
		verdicts = append(verdicts, baseline.Observe(entity, "user", user))
	}
	if len(verdicts) == 0 {
		return
	}
	alerts := []string{}
	for i := range verdicts {
		verdicts[i].Mode = mode
		if verdicts[i].WouldAlert {
			alerts = append(alerts, verdicts[i].Feature+"="+verdicts[i].Value)
		}
	}
	event["behavior_baseline"] = map[string]interface{}{
		"mode":           mode,
		"verdicts":       verdicts,
		"would_alert":    len(alerts) > 0,
		"shadow_only":    mode == behaviorBaselineShadow,
		"advisory":       true,
		"would_alert_on": alerts,
	}
}

// behaviorBaselineRegistry is process-local like the capture registry; a
// restart relearns instead of pretending to know the past.
var behaviorBaselineRegistry = newBehaviorBaseline()

func behaviorBaselineModeFromEnv() string {
	return resolveBehaviorBaselineMode(getEnv("LYFLOW_BEHAVIOR_BASELINE_MODE", behaviorBaselineShadow))
}
