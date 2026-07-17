package replay

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRun_rejects_dirty_checksummed_input(t *testing.T) {
	// Given
	manifest := copyFixtureTree(t)
	rulesPath := filepath.Join(filepath.Dir(manifest), "rules", "v3-shadow.json")
	appendFile(t, rulesPath, []byte("\n"))

	// When
	_, err := Run(context.Background(), Config{ManifestPath: manifest})

	// Then
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("error=%v", err)
	}
}

func TestRun_rejects_malformed_corpus_after_valid_checksum(t *testing.T) {
	// Given
	manifest := copyFixtureTree(t)
	corpusPath := filepath.Join(filepath.Dir(manifest), "corpus.jsonl")
	if err := os.WriteFile(corpusPath, []byte("not-json\n"), 0o644); err != nil {
		t.Fatalf("write malformed corpus: %v", err)
	}
	refreshManifestChecksum(t, manifest, "corpus", corpusPath)

	// When
	_, err := Run(context.Background(), Config{ManifestPath: manifest})

	// Then
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error=%v", err)
	}
}

func TestRun_rejects_stale_baseline_revision(t *testing.T) {
	// Given
	manifest := copyFixtureTree(t)
	baselinePath := filepath.Join(filepath.Dir(manifest), "baseline.json")
	replaceJSONField(t, baselinePath, "manifest_revision", "detection-replay.stale")
	refreshManifestChecksum(t, manifest, "baseline", baselinePath)

	// When
	_, err := Run(context.Background(), Config{ManifestPath: manifest})

	// Then
	if !errors.Is(err, ErrStaleBaseline) {
		t.Fatalf("error=%v", err)
	}
}

func TestRun_rejects_incomplete_corpus_as_regression(t *testing.T) {
	// Given
	manifest := copyFixtureTree(t)
	corpusPath := filepath.Join(filepath.Dir(manifest), "corpus.jsonl")
	replaceInFile(t, corpusPath, `"entity":"host-d"`, `"entity":""`)
	refreshManifestChecksum(t, manifest, "corpus", corpusPath)

	// When
	report, err := Run(context.Background(), Config{ManifestPath: manifest})

	// Then
	if !errors.Is(err, ErrRegression) {
		t.Fatalf("error=%v", err)
	}
	if report.Algorithms[0].Metrics.CompletenessBPS >= 9_375 {
		t.Fatalf("completeness=%d", report.Algorithms[0].Metrics.CompletenessBPS)
	}
}

func TestRun_uses_only_approved_redacted_representative_review_for_calibration(t *testing.T) {
	// Given
	manifest := fixtureManifestPath(t)
	review := approvedReviewPath(t)
	config := Config{ManifestPath: manifest, RepresentativeReviewPath: review, ReviewAsOf: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)}

	// When
	report, err := Run(context.Background(), config)

	// Then
	if err != nil {
		t.Fatalf("run representative calibration: %v", err)
	}
	if report.Qualification != QualificationRepresentativeCalibration || report.RepresentativeReview == nil {
		t.Fatalf("qualification=%q review=%+v", report.Qualification, report.RepresentativeReview)
	}
	if report.PreventionAuthorized || report.CommercialEfficacyAuthorized || report.Algorithms[1].PromotionEligible {
		t.Fatalf("representative review granted forbidden authority: %+v", report)
	}
}

func TestRun_rejects_stale_representative_review(t *testing.T) {
	// Given
	config := Config{
		ManifestPath:             fixtureManifestPath(t),
		RepresentativeReviewPath: approvedReviewPath(t),
		ReviewAsOf:               time.Date(2026, 8, 1, 0, 0, 1, 0, time.UTC),
	}

	// When
	_, err := Run(context.Background(), config)

	// Then
	if !errors.Is(err, ErrStaleReview) {
		t.Fatalf("error=%v", err)
	}
}

func TestRun_rejects_malformed_representative_review(t *testing.T) {
	// Given
	reviewPath := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(reviewPath, []byte(`{"status":"approved"}`), 0o644); err != nil {
		t.Fatalf("write review: %v", err)
	}
	config := Config{ManifestPath: fixtureManifestPath(t), RepresentativeReviewPath: reviewPath, ReviewAsOf: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)}

	// When
	_, err := Run(context.Background(), config)

	// Then
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("error=%v", err)
	}
}

func TestRun_honors_interrupted_context_before_reading_inputs(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// When
	_, err := Run(ctx, Config{ManifestPath: fixtureManifestPath(t)})

	// Then
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}
