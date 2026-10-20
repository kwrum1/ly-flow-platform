// Package stage implements the evidence-gated ATT&CK stage state machine used
// by the correlation service. It is pure in-memory logic so it can be tested
// without ClickHouse or Redis.
package stage

import (
	"sort"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

var order = []contracts.AttackStage{
	contracts.StageRecon,
	contracts.StageInitialAccess,
	contracts.StageExecution,
	contracts.StagePersistence,
	contracts.StagePrivilegeEscalation,
	contracts.StageDefenseEvasion,
	contracts.StageCredentialAccess,
	contracts.StageDiscovery,
	contracts.StageLateralMovement,
	contracts.StageCollection,
	contracts.StageCommandControl,
	contracts.StageExfiltration,
	contracts.StageImpact,
}

type Config struct {
	MaxGap               time.Duration
	MinConfidence        float64
	MaxJump              int
	RequireCorroboration bool
}

func (config Config) withDefaults() Config {
	if config.MaxGap <= 0 {
		config.MaxGap = 24 * time.Hour
	}
	if config.MinConfidence <= 0 {
		config.MinConfidence = 0.5
	}
	if config.MaxJump <= 0 {
		config.MaxJump = 2
	}
	return config
}

type Event struct {
	EventUID    string
	Source      string
	Stage       contracts.AttackStage
	TechniqueID string
	Confidence  float64
	EventAt     time.Time
}

type StageEvidence struct {
	EventUID    string
	Source      string
	Stage       contracts.AttackStage
	TechniqueID string
	Confidence  float64
	EventAt     time.Time
}

type Transition struct {
	Advanced   bool
	From       contracts.AttackStage
	To         contracts.AttackStage
	Reason     string
	Confidence float64
}

type State struct {
	Current    contracts.AttackStage
	Reached    []contracts.AttackStage
	Evidence   []StageEvidence
	Sources    []string
	Confidence float64
	LastAt     time.Time

	seen            map[string]struct{}
	sourceSet       map[string]struct{}
	stageConfidence map[contracts.AttackStage]float64
}

func (state *State) Apply(event Event, config Config) Transition {
	config = config.withDefaults()
	state.init()
	from := state.Current

	if rank(event.Stage) < 0 {
		return Transition{From: from, To: from, Reason: "unknown_stage", Confidence: state.Confidence}
	}
	if event.EventUID != "" {
		if _, exists := state.seen[event.EventUID]; exists {
			return Transition{From: from, To: from, Reason: "duplicate", Confidence: state.Confidence}
		}
		state.seen[event.EventUID] = struct{}{}
	}
	if event.EventAt.IsZero() {
		return Transition{From: from, To: from, Reason: "missing_timestamp", Confidence: state.Confidence}
	}

	if state.Current == "" || state.Current == contracts.StageUnknown {
		state.advance(event)
		return Transition{Advanced: true, From: from, To: state.Current, Reason: "initial", Confidence: state.Confidence}
	}

	currentRank := rank(state.Current)
	eventRank := rank(event.Stage)
	if eventRank < currentRank {
		state.addEvidence(event)
		return Transition{From: from, To: state.Current, Reason: "regressed", Confidence: state.Confidence}
	}
	if eventRank == currentRank {
		state.addEvidence(event)
		return Transition{From: from, To: state.Current, Reason: "same_stage", Confidence: state.Confidence}
	}
	if !state.LastAt.IsZero() && event.EventAt.Before(state.LastAt) {
		return Transition{From: from, To: state.Current, Reason: "out_of_order", Confidence: state.Confidence}
	}
	if !state.LastAt.IsZero() && event.EventAt.Sub(state.LastAt) > config.MaxGap {
		return Transition{From: from, To: state.Current, Reason: "out_of_window", Confidence: state.Confidence}
	}
	if eventRank-currentRank > config.MaxJump {
		return Transition{From: from, To: state.Current, Reason: "jump_too_large", Confidence: state.Confidence}
	}
	if event.Confidence < config.MinConfidence {
		return Transition{From: from, To: state.Current, Reason: "low_confidence", Confidence: state.Confidence}
	}
	if config.RequireCorroboration && !state.hasCorroboration(event.Source) {
		return Transition{From: from, To: state.Current, Reason: "needs_corroboration", Confidence: state.Confidence}
	}

	state.advance(event)
	return Transition{Advanced: true, From: from, To: state.Current, Reason: "advanced", Confidence: state.Confidence}
}

type Snapshot struct {
	Current    contracts.AttackStage
	Reached    []contracts.AttackStage
	Evidence   []StageEvidence
	Sources    []string
	Confidence float64
	LastAt     time.Time
}

func (state *State) Snapshot() Snapshot {
	state.init()
	return Snapshot{
		Current:    state.Current,
		Reached:    append([]contracts.AttackStage(nil), state.Reached...),
		Evidence:   append([]StageEvidence(nil), state.Evidence...),
		Sources:    append([]string(nil), state.Sources...),
		Confidence: state.Confidence,
		LastAt:     state.LastAt,
	}
}

func (state *State) init() {
	if state.seen == nil {
		state.seen = map[string]struct{}{}
	}
	if state.sourceSet == nil {
		state.sourceSet = map[string]struct{}{}
	}
	if state.stageConfidence == nil {
		state.stageConfidence = map[contracts.AttackStage]float64{}
	}
}

func (state *State) advance(event Event) {
	if state.Current != event.Stage {
		state.Current = event.Stage
		state.Reached = append(state.Reached, event.Stage)
	}
	state.addEvidence(event)
	if state.LastAt.IsZero() || event.EventAt.After(state.LastAt) {
		state.LastAt = event.EventAt
	}
}

func (state *State) addEvidence(event Event) {
	state.Evidence = append(state.Evidence, StageEvidence{
		EventUID: event.EventUID, Source: event.Source, Stage: event.Stage,
		TechniqueID: event.TechniqueID, Confidence: event.Confidence, EventAt: event.EventAt,
	})
	if event.Source != "" {
		if _, exists := state.sourceSet[event.Source]; !exists {
			state.sourceSet[event.Source] = struct{}{}
			state.Sources = append(state.Sources, event.Source)
			sort.Strings(state.Sources)
		}
	}
	if event.Confidence > state.stageConfidence[event.Stage] {
		state.stageConfidence[event.Stage] = event.Confidence
	}
	state.recomputeConfidence()
	if state.LastAt.IsZero() || event.EventAt.After(state.LastAt) {
		state.LastAt = event.EventAt
	}
}

func (state *State) recomputeConfidence() {
	if len(state.Reached) == 0 {
		state.Confidence = 0
		return
	}
	total := 0.0
	for _, reached := range state.Reached {
		total += state.stageConfidence[reached]
	}
	state.Confidence = total / float64(len(state.Reached))
}

func (state *State) hasCorroboration(incomingSource string) bool {
	count := len(state.sourceSet)
	if incomingSource != "" {
		if _, exists := state.sourceSet[incomingSource]; !exists {
			count++
		}
	}
	return count >= 2
}

func rank(stage contracts.AttackStage) int {
	for index, candidate := range order {
		if candidate == stage {
			return index
		}
	}
	return -1
}
