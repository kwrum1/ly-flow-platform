package main

import (
	"testing"
	"time"
)

func TestBehaviorBaselineDoesNotFlagBeforeWarmup(t *testing.T) {
	baseline := newBehaviorBaseline()
	for i := 0; i < behaviorBaselineMinSupport-1; i++ {
		verdict := baseline.Observe("host-a", "process", "/usr/sbin/nginx")
		if verdict.WouldAlert {
			t.Fatalf("alerted during warmup at observation %d", i)
		}
	}
	novel := baseline.Observe("host-a", "process", "curl")
	if novel.WouldAlert {
		t.Fatal("warmup boundary must not alert: support is still below the minimum")
	}
	// The observation above counts, so the next new value is judged.
	next := baseline.Observe("host-a", "process", "wget")
	if !next.Novel || !next.WouldAlert {
		t.Fatalf("mature baseline must flag a new process: %+v", next)
	}
}

func TestBehaviorBaselineLearnsNormal(t *testing.T) {
	baseline := newBehaviorBaseline()
	for i := 0; i < behaviorBaselineMinSupport*2; i++ {
		baseline.Observe("host-a", "process", "/usr/sbin/nginx")
	}
	verdict := baseline.Observe("host-a", "process", "/usr/sbin/nginx")
	if verdict.Novel || verdict.WouldAlert {
		t.Fatalf("known value was flagged: %+v", verdict)
	}
	if verdict.Support < behaviorBaselineMinSupport {
		t.Fatalf("support = %d", verdict.Support)
	}
}

func TestBehaviorBaselineIsPerEntity(t *testing.T) {
	baseline := newBehaviorBaseline()
	for i := 0; i < behaviorBaselineMinSupport*2; i++ {
		baseline.Observe("host-a", "process", "/usr/sbin/nginx")
	}
	// host-b has its own (empty) baseline and must not inherit host-a's:
	// the value is novel but the baseline is not mature enough to judge it.
	verdict := baseline.Observe("host-b", "process", "/usr/sbin/nginx")
	if !verdict.Novel || verdict.WouldAlert {
		t.Fatalf("fresh entity must not be judged: %+v", verdict)
	}
}

func TestBehaviorBaselineSaturatesInsteadOfForgetting(t *testing.T) {
	baseline := newBehaviorBaseline()
	for i := 0; i < baseline.maxSize; i++ {
		baseline.Observe("host-a", "process", "proc-"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	for i := 0; i < behaviorBaselineMinSupport*2; i++ {
		baseline.Observe("host-a", "process", "proc-aa")
	}
	verdict := baseline.Observe("host-a", "process", "brand-new")
	if verdict.WouldAlert {
		t.Fatal("saturated series must not alert on unseen values")
	}
	if verdict.Feature != "process:saturated" {
		t.Fatalf("feature = %q", verdict.Feature)
	}
}

func TestResolveBehaviorBaselineMode(t *testing.T) {
	cases := map[string]string{
		"":        behaviorBaselineShadow,
		"off":     behaviorBaselineOff,
		"SHADOW":  behaviorBaselineShadow,
		"enforce": behaviorBaselineEnforce,
		"bogus":   behaviorBaselineShadow,
	}
	for input, want := range cases {
		if got := resolveBehaviorBaselineMode(input); got != want {
			t.Fatalf("%q => %q, want %q", input, got, want)
		}
	}
}

func TestAnnotateBehaviorBaselineIsAdvisory(t *testing.T) {
	baseline := newBehaviorBaseline()
	for i := 0; i < behaviorBaselineMinSupport*2; i++ {
		baseline.Observe("host-a", "process", "/usr/sbin/nginx")
	}
	event := map[string]interface{}{
		"agent_id":     "host-a",
		"process_name": "curl",
		"score_hint":   int64(40),
		"severity":     "medium",
	}
	annotateBehaviorBaseline(event, baseline, behaviorBaselineShadow)

	annotation, ok := event["behavior_baseline"].(map[string]interface{})
	if !ok {
		t.Fatal("annotation missing")
	}
	if annotation["shadow_only"] != true || annotation["advisory"] != true {
		t.Fatalf("shadow annotation must stay advisory: %+v", annotation)
	}
	if annotation["would_alert"] != true {
		t.Fatal("novel process should be reported as a shadow would-alert")
	}
	if event["score_hint"].(int64) != 40 || event["severity"] != "medium" {
		t.Fatal("annotation must not change score or severity")
	}
}

func TestAnnotateBehaviorBaselineSkipsMissingEntity(t *testing.T) {
	baseline := newBehaviorBaseline()
	event := map[string]interface{}{"process_name": "curl"}
	annotateBehaviorBaseline(event, baseline, behaviorBaselineShadow)
	if _, ok := event["behavior_baseline"]; ok {
		t.Fatal("event without entity must not be judged")
	}
}

func TestFeedbackScopeValidation(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		scope feedbackScope
		want  error
	}{
		{"missing rule", feedbackScope{Entity: "host-a"}, errFeedbackRuleRequired},
		{"wildcard rule", feedbackScope{RuleID: "*", Entity: "host-a"}, errFeedbackRuleRequired},
		{"missing entity", feedbackScope{RuleID: "5710", Entity: ""}, errFeedbackScopeTooBroad},
		{"wildcard entity", feedbackScope{RuleID: "5710", Entity: "*"}, errFeedbackScopeTooBroad},
		{"expired", feedbackScope{RuleID: "5710", Entity: "host-a", ExpiresAt: now.Add(-time.Hour)}, errFeedbackExpiryInvalid},
		{"too long", feedbackScope{RuleID: "5710", Entity: "host-a", ExpiresAt: now.Add(60 * 24 * time.Hour)}, errFeedbackExpiryInvalid},
		{"ok default ttl", feedbackScope{RuleID: "5710", Entity: "host-a"}, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateFeedbackScope(testCase.scope, now)
			if testCase.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != testCase.want {
				t.Fatalf("err = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestFeedbackAdjustmentIsShadowCandidate(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	adjustment, err := adjustmentFromFeedback(feedbackScope{
		TenantID: "default", RuleID: "5710", Entity: "host-a", Note: "lab scanner",
	}, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !adjustment.Shadow {
		t.Fatal("feedback must produce a shadow candidate, not an applied change")
	}
	if adjustment.Kind != "raise_threshold" {
		t.Fatalf("kind = %q", adjustment.Kind)
	}
	if adjustment.Scope.ExpiresAt.IsZero() || adjustment.Scope.ExpiresAt.After(now.Add(feedbackMaxLifetime)) {
		t.Fatalf("expiry = %v", adjustment.Scope.ExpiresAt)
	}
}

func TestFeedbackAppliesOnlyInsideScope(t *testing.T) {
	now := time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC)
	adjustment, err := adjustmentFromFeedback(feedbackScope{
		TenantID: "default", RuleID: "5710", Entity: "host-a",
		ExpiresAt: now.Add(24 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !feedbackAdjustmentActive(adjustment, "default", "5710", "host-a", now.Add(time.Hour)) {
		t.Fatal("in-scope event was not covered")
	}
	if feedbackAdjustmentActive(adjustment, "default", "5710", "host-b", now.Add(time.Hour)) {
		t.Fatal("other entity was covered")
	}
	if feedbackAdjustmentActive(adjustment, "other-tenant", "5710", "host-a", now.Add(time.Hour)) {
		t.Fatal("other tenant was covered")
	}
	if feedbackAdjustmentActive(adjustment, "default", "5711", "host-a", now.Add(time.Hour)) {
		t.Fatal("other rule was covered")
	}
	if feedbackAdjustmentActive(adjustment, "default", "5710", "host-a", now.Add(48*time.Hour)) {
		t.Fatal("expired candidate was still applied")
	}
	if feedbackAdjustmentActive(adjustment, "", "5710", "host-a", now.Add(time.Hour)) {
		t.Fatal("missing tenant was treated as a match")
	}
}
