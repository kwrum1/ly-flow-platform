package replay

import (
	"encoding/json"
	"fmt"
)

func EncodeReports(report Report) ([]byte, []byte, error) {
	if err := validateReport(report); err != nil {
		return nil, nil, err
	}
	machine, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode machine replay report: %w", err)
	}
	machine = append(machine, '\n')
	scope := "Synthetic regression only"
	if report.Qualification == QualificationRepresentativeCalibration {
		scope = "Approved redacted representative-data calibration"
	}
	human := fmt.Sprintf(`# Detection replay report

Status | %s
Qualification | %s
Scope | %s
Manifest revision | %s
v2-active precision/recall/FPR/completeness (bps) | %d/%d/%d/%d
v3-shadow precision/recall/FPR/completeness (bps) | %d/%d/%d/%d
Recall delta (bps) | %d
v3-shadow promotion | structurally forbidden
Prevention authorization | forbidden
Commercial efficacy authorization | forbidden
`, report.Status, report.Qualification, scope, report.ManifestRevision,
		report.Algorithms[0].Metrics.PrecisionBPS, report.Algorithms[0].Metrics.RecallBPS, report.Algorithms[0].Metrics.FalsePositiveRateBPS, report.Algorithms[0].Metrics.CompletenessBPS,
		report.Algorithms[1].Metrics.PrecisionBPS, report.Algorithms[1].Metrics.RecallBPS, report.Algorithms[1].Metrics.FalsePositiveRateBPS, report.Algorithms[1].Metrics.CompletenessBPS,
		report.Deltas.RecallBPS)
	return machine, []byte(human), nil
}

func VerifyMachineReport(contents []byte) error {
	var report Report
	if err := decodeStrict("machine report", contents, &report); err != nil {
		return err
	}
	return validateReport(report)
}
