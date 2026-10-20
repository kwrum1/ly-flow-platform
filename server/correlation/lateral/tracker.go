package lateral

import (
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

// Tracker keeps a bounded rolling window of normalized events and emits one
// finding per source/target set per cooldown period. It is intentionally
// state-light so it can run inside the ingest process without a new datastore.
type Tracker struct {
	config   Config
	maxEvents int
	cooldown time.Duration
	events   []contracts.EventV2
	emitted  map[string]time.Time
	now      func() time.Time
}

func NewTracker(config Config) *Tracker {
	config = config.withDefaults()
	if config.Window <= 0 {
		config.Window = 10 * time.Minute
	}
	return &Tracker{
		config: config, maxEvents: 5000, cooldown: config.Window,
		emitted: map[string]time.Time{}, now: time.Now,
	}
}

func (tracker *Tracker) Observe(batch []contracts.EventV2) []Finding {
	if tracker == nil || len(batch) == 0 {
		return nil
	}
	now := tracker.now().UTC()
	tracker.events = append(tracker.events, batch...)
	tracker.prune(now)
	findings := Detect(tracker.events, tracker.config)
	fresh := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := findingKey(finding)
		if last, ok := tracker.emitted[key]; ok && now.Sub(last) < tracker.cooldown {
			continue
		}
		tracker.emitted[key] = now
		fresh = append(fresh, finding)
	}
	for key, at := range tracker.emitted {
		if now.Sub(at) > 4*tracker.cooldown {
			delete(tracker.emitted, key)
		}
	}
	return fresh
}

// Events returns a copy of the bounded rolling window for derived-event
// projection and tests.
func (tracker *Tracker) Events() []contracts.EventV2 {
	if tracker == nil {
		return nil
	}
	out := make([]contracts.EventV2, len(tracker.events))
	copy(out, tracker.events)
	return out
}

func (tracker *Tracker) prune(now time.Time) {
	cutoff := now.Add(-2 * tracker.config.Window)
	kept := tracker.events[:0]
	for _, event := range tracker.events {
		if event.Timestamps.EventAt.IsZero() || event.Timestamps.EventAt.After(cutoff) {
			kept = append(kept, event)
		}
	}
	if len(kept) > tracker.maxEvents {
		kept = kept[len(kept)-tracker.maxEvents:]
	}
	tracker.events = kept
}

func findingKey(finding Finding) string {
	return finding.Type + "|" + finding.Source + "|" + strings.Join(finding.Targets, ",")
}
