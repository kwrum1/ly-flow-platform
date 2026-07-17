package replay

import (
	"context"
	"fmt"
)

func Run(ctx context.Context, config Config) (Report, error) {
	if config.ManifestPath == "" {
		return Report{}, &MalformedError{Path: "config", Reason: "manifest path is required"}
	}
	inputs, err := loadInputs(ctx, config.ManifestPath)
	if err != nil {
		return Report{}, err
	}
	results := make([]AlgorithmResult, len(inputs.algorithms))
	for index, algorithm := range inputs.algorithms {
		results[index] = AlgorithmResult{
			Identity: algorithm.reference.Identity, DescriptorSHA256: algorithm.reference.DescriptorSHA256,
			RulesSHA256: algorithm.reference.RulesSHA256, Metrics: evaluate(inputs.corpus, algorithm.rules), PromotionEligible: false,
		}
	}
	report := Report{
		SchemaVersion: "lyflow.detection-replay-report.v1", ManifestRevision: inputs.manifest.Revision,
		Status: StatusPass, Qualification: QualificationSyntheticRegression,
		Inputs:     InputChecksums{ManifestSHA256: inputs.manifestDigest, CorpusSHA256: inputs.manifest.Corpus.SHA256, BaselineSHA256: inputs.manifest.Baseline.SHA256, WorkflowSHA256: inputs.manifest.Workflow.SHA256},
		Algorithms: results, Deltas: delta(results[0].Metrics, results[1].Metrics),
		PreventionAuthorized: false, CommercialEfficacyAuthorized: false,
	}
	if config.RepresentativeReviewPath != "" {
		review, err := loadRepresentativeReview(config, inputs)
		if err != nil {
			return Report{}, err
		}
		report.Qualification = QualificationRepresentativeCalibration
		report.RepresentativeReview = review
	}
	reasons := regressionReasons(inputs.baseline, results)
	if len(reasons) != 0 {
		report.Status = StatusFail
		return report, &RegressionError{Reasons: reasons}
	}
	return report, nil
}

func evaluate(records []corpusRecord, rules ruleSet) Metrics {
	matched := make(map[string]struct{}, len(rules.MatchIDs))
	for _, id := range rules.MatchIDs {
		matched[id] = struct{}{}
	}
	metrics := Metrics{}
	complete := 0
	for _, record := range records {
		if record.Entity != "" {
			complete++
		}
		if record.Source != "" {
			complete++
		}
		_, selected := matched[record.ID]
		selected = selected || rules.MatchAll
		switch {
		case selected && record.Expected:
			metrics.TruePositive++
		case selected && !record.Expected:
			metrics.FalsePositive++
		case !selected && record.Expected:
			metrics.FalseNegative++
		default:
			metrics.TrueNegative++
		}
	}
	metrics.PrecisionBPS = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalsePositive)
	metrics.RecallBPS = ratio(metrics.TruePositive, metrics.TruePositive+metrics.FalseNegative)
	metrics.FalsePositiveRateBPS = ratio(metrics.FalsePositive, metrics.FalsePositive+metrics.TrueNegative)
	metrics.CompletenessBPS = ratio(complete, len(records)*2)
	return metrics
}

func ratio(numerator, denominator int) int {
	if denominator == 0 {
		return 10_000
	}
	return numerator * 10_000 / denominator
}

func delta(active, shadow Metrics) MetricDeltas {
	return MetricDeltas{
		PrecisionBPS:         shadow.PrecisionBPS - active.PrecisionBPS,
		RecallBPS:            shadow.RecallBPS - active.RecallBPS,
		FalsePositiveRateBPS: shadow.FalsePositiveRateBPS - active.FalsePositiveRateBPS,
		CompletenessBPS:      shadow.CompletenessBPS - active.CompletenessBPS,
	}
}

func regressionReasons(approved baseline, results []AlgorithmResult) []string {
	active, shadow := results[0].Metrics, results[1].Metrics
	reasons := make([]string, 0, 5)
	if active != approved.Active {
		reasons = append(reasons, "v2-active differs from immutable baseline")
	}
	if shadow.RecallBPS < approved.MinimumShadowRecallBPS {
		reasons = append(reasons, "v3-shadow recall below baseline gate")
	}
	if shadow.FalsePositiveRateBPS > approved.MaximumShadowFPRBPS {
		reasons = append(reasons, "v3-shadow false-positive rate above baseline gate")
	}
	if active.CompletenessBPS < approved.MinimumCompletenessBPS || shadow.CompletenessBPS < approved.MinimumCompletenessBPS {
		reasons = append(reasons, "corpus completeness below baseline gate")
	}
	return reasons
}

func validateReport(report Report) error {
	if report.SchemaVersion != "lyflow.detection-replay-report.v1" || report.ManifestRevision == "" || len(report.Algorithms) != 2 {
		return &MalformedError{Path: "machine report", Reason: "missing required report identity"}
	}
	if report.Status != StatusPass && report.Status != StatusFail {
		return &MalformedError{Path: "machine report", Reason: "invalid status"}
	}
	if report.Qualification != QualificationSyntheticRegression && report.Qualification != QualificationRepresentativeCalibration {
		return &MalformedError{Path: "machine report", Reason: "invalid qualification"}
	}
	if (report.Qualification == QualificationRepresentativeCalibration) != (report.RepresentativeReview != nil) {
		return &MalformedError{Path: "machine report", Reason: "representative qualification and review metadata disagree"}
	}
	if report.Algorithms[0].Identity != "v2-active" || report.Algorithms[1].Identity != "v3-shadow" {
		return &MalformedError{Path: "machine report", Reason: "algorithm identities are not side-by-side active and shadow"}
	}
	if report.Algorithms[1].PromotionEligible || report.PreventionAuthorized || report.CommercialEfficacyAuthorized {
		return &MalformedError{Path: "machine report", Reason: "report grants structurally forbidden authority"}
	}
	for name, checksum := range map[string]string{"manifest": report.Inputs.ManifestSHA256, "corpus": report.Inputs.CorpusSHA256, "baseline": report.Inputs.BaselineSHA256, "workflow": report.Inputs.WorkflowSHA256} {
		if len(checksum) != 64 {
			return &MalformedError{Path: "machine report", Reason: fmt.Sprintf("invalid %s checksum", name)}
		}
	}
	for _, algorithm := range report.Algorithms {
		if len(algorithm.DescriptorSHA256) != 64 || len(algorithm.RulesSHA256) != 64 || !validMetrics(algorithm.Metrics) {
			return &MalformedError{Path: "machine report", Reason: fmt.Sprintf("invalid algorithm result for %s", algorithm.Identity)}
		}
	}
	return nil
}

func validMetrics(metrics Metrics) bool {
	values := []int{metrics.PrecisionBPS, metrics.RecallBPS, metrics.FalsePositiveRateBPS, metrics.CompletenessBPS}
	for _, value := range values {
		if value < 0 || value > 10_000 {
			return false
		}
	}
	return metrics.TruePositive >= 0 && metrics.FalsePositive >= 0 && metrics.TrueNegative >= 0 && metrics.FalseNegative >= 0
}
