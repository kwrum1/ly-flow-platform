package contracts

import (
	"context"
	"errors"
	"time"
)

var ErrRetirementHorizonUnavailable = errors.New("Todo 7 retirement horizon unavailable")

const RetirementEvidenceFreshness = 5 * time.Minute

type PersistedRetirementHorizon struct {
	persisted                bool
	maximumSpoolRetryHorizon time.Duration
	zeroLegacyReadsSince     time.Time
	allProducersUpgraded     bool
	persistedAt              time.Time
}

func NewPersistedRetirementHorizon(maximum time.Duration, zeroReadsSince time.Time, allProducersUpgraded bool, persistedAt time.Time) (PersistedRetirementHorizon, error) {
	if maximum <= 0 || zeroReadsSince.IsZero() || persistedAt.IsZero() {
		return PersistedRetirementHorizon{}, ErrRetirementHorizonUnavailable
	}
	return PersistedRetirementHorizon{
		persisted: true, maximumSpoolRetryHorizon: maximum,
		zeroLegacyReadsSince: zeroReadsSince.UTC(), allProducersUpgraded: allProducersUpgraded,
		persistedAt: persistedAt.UTC(),
	}, nil
}

type RetirementHorizonSource interface {
	Load(context.Context) (PersistedRetirementHorizon, error)
}

type DisabledRetirementHorizonSource struct{}

func (DisabledRetirementHorizonSource) Load(context.Context) (PersistedRetirementHorizon, error) {
	return PersistedRetirementHorizon{}, ErrRetirementHorizonUnavailable
}

type RetirementGate struct {
	Enabled bool `json:"enabled"`
}

type RetirementStatus struct {
	Allowed    bool   `json:"allowed"`
	Dependency string `json:"dependency"`
	Reason     string `json:"reason"`
}

func (gate RetirementGate) Evaluate(ctx context.Context, source RetirementHorizonSource, now time.Time) RetirementStatus {
	const dependency = "Todo 7 persisted maximum spool/retry horizon"
	if !gate.Enabled {
		return RetirementStatus{Dependency: dependency, Reason: "retire_legacy is defined but disabled during Todo 6"}
	}
	if source == nil {
		return RetirementStatus{Dependency: dependency, Reason: ErrRetirementHorizonUnavailable.Error()}
	}
	evidence, err := source.Load(ctx)
	if err != nil || !evidence.persisted || evidence.maximumSpoolRetryHorizon <= 0 || evidence.zeroLegacyReadsSince.IsZero() {
		return RetirementStatus{Dependency: dependency, Reason: "maximum spool/retry horizon is not persisted"}
	}
	if !evidence.allProducersUpgraded {
		return RetirementStatus{Dependency: dependency, Reason: "not every producer is upgraded"}
	}
	if evidence.persistedAt.After(now) || now.Sub(evidence.persistedAt) > RetirementEvidenceFreshness {
		return RetirementStatus{Dependency: dependency, Reason: "persisted retirement evidence is stale"}
	}
	if now.Sub(evidence.zeroLegacyReadsSince) < evidence.maximumSpoolRetryHorizon {
		return RetirementStatus{Dependency: dependency, Reason: "zero legacy reads has not covered the full persisted horizon"}
	}
	return RetirementStatus{Allowed: true, Dependency: dependency, Reason: "retirement prerequisites satisfied"}
}
