package contracts

type MigrationWarning string

const (
	WarningLegacyReadsRemaining   MigrationWarning = "legacy_reads_remaining"
	WarningReconciliationMismatch MigrationWarning = "reconciliation_mismatch"
)

type MigrationObservationInput struct {
	LegacyReads         uint64
	CanonicalReads      uint64
	Quarantined         uint64
	ReconciliationMatch bool
}

type MigrationObservation struct {
	LegacyReads         uint64             `json:"legacy_reads"`
	CanonicalReads      uint64             `json:"canonical_reads"`
	Quarantined         uint64             `json:"quarantined"`
	LegacyReadRatio     float64            `json:"legacy_read_ratio"`
	ReconciliationMatch bool               `json:"reconciliation_match"`
	Warnings            []MigrationWarning `json:"warnings"`
}

func ObserveMigration(input MigrationObservationInput) MigrationObservation {
	totalReads := input.LegacyReads + input.CanonicalReads
	legacyReadRatio := 0.0
	if totalReads > 0 {
		legacyReadRatio = float64(input.LegacyReads) / float64(totalReads)
	}
	warnings := make([]MigrationWarning, 0, 2)
	if input.LegacyReads > 0 {
		warnings = append(warnings, WarningLegacyReadsRemaining)
	}
	if !input.ReconciliationMatch {
		warnings = append(warnings, WarningReconciliationMismatch)
	}
	return MigrationObservation{
		LegacyReads: input.LegacyReads, CanonicalReads: input.CanonicalReads, Quarantined: input.Quarantined,
		LegacyReadRatio: legacyReadRatio, ReconciliationMatch: input.ReconciliationMatch, Warnings: warnings,
	}
}
