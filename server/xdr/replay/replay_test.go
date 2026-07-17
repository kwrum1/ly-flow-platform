package replay

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRun_replays_active_and_shadow_deterministically_on_inert_corpus(t *testing.T) {
	// Given
	config := Config{ManifestPath: fixtureManifestPath(t)}

	// When
	first, firstErr := Run(context.Background(), config)
	second, secondErr := Run(context.Background(), config)

	// Then
	if firstErr != nil || secondErr != nil {
		t.Fatalf("run replay twice: first=%v second=%v", firstErr, secondErr)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("replay is not deterministic:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.Status != StatusPass || first.Qualification != QualificationSyntheticRegression {
		t.Fatalf("status=%q qualification=%q", first.Status, first.Qualification)
	}
	if len(first.Algorithms) != 2 {
		t.Fatalf("algorithm count=%d", len(first.Algorithms))
	}
	active := first.Algorithms[0]
	shadow := first.Algorithms[1]
	if active.Identity != "v2-active" || active.Metrics.PrecisionBPS != 10_000 || active.Metrics.RecallBPS != 7_500 || active.Metrics.FalsePositiveRateBPS != 0 || active.Metrics.CompletenessBPS != 9_375 {
		t.Fatalf("active result=%+v", active)
	}
	if shadow.Identity != "v3-shadow" || shadow.Metrics.PrecisionBPS != 10_000 || shadow.Metrics.RecallBPS != 10_000 || shadow.Metrics.FalsePositiveRateBPS != 0 || shadow.Metrics.CompletenessBPS != 9_375 {
		t.Fatalf("shadow result=%+v", shadow)
	}
	if first.Deltas.RecallBPS != 2_500 || first.Deltas.PrecisionBPS != 0 || first.Deltas.FalsePositiveRateBPS != 0 || first.Deltas.CompletenessBPS != 0 {
		t.Fatalf("deltas=%+v", first.Deltas)
	}
	if shadow.PromotionEligible || first.PreventionAuthorized || first.CommercialEfficacyAuthorized {
		t.Fatalf("synthetic replay granted forbidden authority: %+v", first)
	}
	for name, checksum := range map[string]string{
		"manifest": first.Inputs.ManifestSHA256,
		"corpus":   first.Inputs.CorpusSHA256,
		"baseline": first.Inputs.BaselineSHA256,
		"workflow": first.Inputs.WorkflowSHA256,
	} {
		if len(checksum) != 64 {
			t.Fatalf("%s checksum=%q", name, checksum)
		}
	}
}

func TestRun_fails_regression_gate_for_deliberately_overbroad_inert_rule(t *testing.T) {
	// Given
	manifest := copyFixtureTree(t)
	replaceShadowRules(t, manifest, "rules/v3-shadow-overbroad.inert-test.json")

	// When
	report, err := Run(context.Background(), Config{ManifestPath: manifest})

	// Then
	if !errors.Is(err, ErrRegression) {
		t.Fatalf("error=%v", err)
	}
	if report.Status != StatusFail || report.Algorithms[1].Metrics.FalsePositiveRateBPS != 10_000 {
		t.Fatalf("overbroad report=%+v", report)
	}
	if report.Algorithms[1].PromotionEligible {
		t.Fatal("failed shadow regression became promotable")
	}
}
