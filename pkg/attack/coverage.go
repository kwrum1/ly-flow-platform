package attack

import (
	"sort"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type Coverage struct {
	KnownTactics       int
	KnownTechniques    int
	ObservedTechniques int
	Coverage           float64
	Tactics            []TacticCoverage
}

type TacticCoverage struct {
	TacticID   string
	Name       string
	Observed   int
	Techniques []TechniqueCoverage
}

type TechniqueCoverage struct {
	TechniqueID string
	Name        string
	Count       int
}

// BuildCoverage computes sample coverage from already-normalized events. It is
// deliberately based on the static ATT&CK table so callers can show a stable
// denominator even when a time window contains only a few events.
func BuildCoverage(events []contracts.EventV2) Coverage {
	counts := map[string]int{}
	tacticCounts := map[string]int{}
	for _, event := range events {
		techniqueID := normalizeID(event.Detection.TechniqueID)
		tacticID := normalizeID(event.Detection.TacticID)
		if techniqueID != "" {
			if technique, ok := techniqueByID[techniqueID]; ok {
				counts[techniqueID]++
				if tacticID == "" {
					tacticID = technique.TacticID
				}
			}
		}
		if tacticID != "" {
			tacticCounts[tacticID]++
		}
	}

	report := Coverage{
		KnownTactics:       len(Tactics),
		KnownTechniques:    len(Techniques),
		ObservedTechniques: len(counts),
	}
	if report.KnownTechniques > 0 {
		report.Coverage = float64(report.ObservedTechniques) / float64(report.KnownTechniques)
	}
	for _, tactic := range Tactics {
		coverage := TacticCoverage{TacticID: tactic.ID, Name: tactic.Name, Observed: tacticCounts[tactic.ID]}
		for _, technique := range Techniques {
			if technique.TacticID != tactic.ID {
				continue
			}
			if count := counts[technique.ID]; count > 0 {
				coverage.Techniques = append(coverage.Techniques, TechniqueCoverage{
					TechniqueID: technique.ID, Name: technique.Name, Count: count,
				})
			}
		}
		sort.SliceStable(coverage.Techniques, func(left, right int) bool {
			if coverage.Techniques[left].Count == coverage.Techniques[right].Count {
				return coverage.Techniques[left].TechniqueID < coverage.Techniques[right].TechniqueID
			}
			return coverage.Techniques[left].Count > coverage.Techniques[right].Count
		})
		report.Tactics = append(report.Tactics, coverage)
	}
	return report
}
