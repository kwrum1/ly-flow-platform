package rulelifecycle

import (
	"context"
	"os"
	"testing"
)

func TestActiveRuleCountsRequiresVerifiedActiveBundle(t *testing.T) {
	// Given
	manager, _, _ := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	bundle := validBundle("count-1", "rule-1")
	pin := SourcePin{URL: "https://rules.example.test/count-1", Revision: "count-1", SHA256: sha256Hex(bundle)}
	if _, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: pin, FinalURL: pin.URL, Content: bundle, verified: true}); err != nil {
		t.Fatalf("stage count bundle: %v", err)
	}
	manifest, err := manager.Activate(context.Background(), actor, pin.Revision)
	if err != nil {
		t.Fatalf("activate count bundle: %v", err)
	}

	// When
	counts, countErr := manager.ActiveRuleCounts(context.Background())

	// Then
	if countErr != nil || counts["runtime"] != 1 {
		t.Fatalf("active counts=%#v error=%v", counts, countErr)
	}
	if err := os.WriteFile(manifest.BundlePath, append(bundle, ' '), lifecycleFileMode); err != nil {
		t.Fatalf("tamper active bundle: %v", err)
	}
	if _, err := manager.ActiveRuleCounts(context.Background()); err == nil {
		t.Fatal("tampered active bundle produced trusted counts")
	}
}
