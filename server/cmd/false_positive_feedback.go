package main

import (
	"errors"
	"strings"
	"time"
)

// T4-02 false-positive feedback must be bounded, expiring and reviewable.
//
// Feedback never suppresses detections directly. It only produces a candidate
// tuning (for example "raise this rule's threshold for this entity") that is
// stored in shadow and expires. A candidate that matches everything is
// rejected outright: "always ignore" is not a supported outcome.

const (
	feedbackMaxLifetime = 30 * 24 * time.Hour
	feedbackDefaultTTL  = 7 * 24 * time.Hour
)

var (
	errFeedbackRuleRequired   = errors.New("feedback requires a rule")
	errFeedbackTenantRequired = errors.New("feedback requires a tenant")
	errFeedbackScopeTooBroad  = errors.New("feedback scope is too broad: entity or explicit tenant scope required")
	errFeedbackExpiryInvalid  = errors.New("feedback expiry must be in the future and at most 30 days")
)

type feedbackScope struct {
	TenantID  string    `json:"tenant_id"`
	RuleID    string    `json:"rule_id"`
	Entity    string    `json:"entity"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// candidateAdjustment is the only thing feedback is allowed to produce.
type candidateAdjustment struct {
	Kind   string        `json:"kind"`
	Scope  feedbackScope `json:"scope"`
	Shadow bool          `json:"shadow"`
}

func normalizeFeedbackScope(scope feedbackScope, now time.Time) feedbackScope {
	scope.TenantID = strings.TrimSpace(scope.TenantID)
	scope.RuleID = strings.TrimSpace(scope.RuleID)
	scope.Entity = strings.TrimSpace(scope.Entity)
	if scope.TenantID == "" {
		scope.TenantID = "default"
	}
	if scope.CreatedAt.IsZero() {
		scope.CreatedAt = now
	}
	if scope.ExpiresAt.IsZero() {
		scope.ExpiresAt = now.Add(feedbackDefaultTTL)
	}
	return scope
}

// validateFeedbackScope enforces a bounded, expiring scope.
func validateFeedbackScope(scope feedbackScope, now time.Time) error {
	scope = normalizeFeedbackScope(scope, now)
	if scope.RuleID == "" || scope.RuleID == "*" {
		return errFeedbackRuleRequired
	}
	if scope.TenantID == "" || scope.TenantID == "*" {
		return errFeedbackTenantRequired
	}
	if scope.Entity == "" || scope.Entity == "*" {
		return errFeedbackScopeTooBroad
	}
	if !scope.ExpiresAt.After(now) || scope.ExpiresAt.Sub(now) > feedbackMaxLifetime {
		return errFeedbackExpiryInvalid
	}
	return nil
}

// adjustmentFromFeedback turns accepted feedback into a shadow candidate.
func adjustmentFromFeedback(scope feedbackScope, now time.Time) (candidateAdjustment, error) {
	scope = normalizeFeedbackScope(scope, now)
	if err := validateFeedbackScope(scope, now); err != nil {
		return candidateAdjustment{}, err
	}
	return candidateAdjustment{
		Kind:   "raise_threshold",
		Scope:  scope,
		Shadow: true,
	}, nil
}

func feedbackActive(scope feedbackScope, now time.Time) bool {
	if scope.RuleID == "" || scope.TenantID == "" || scope.Entity == "" {
		return false
	}
	return now.Before(scope.ExpiresAt)
}

// feedbackAppliesTo reports whether a candidate event is inside the scope.
// Tenant, rule and entity must all match; an empty field on either side never
// matches, so missing data cannot widen the scope.
func feedbackAppliesTo(scope feedbackScope, tenantID, ruleID, entity string, now time.Time) bool {
	if !feedbackActive(scope, now) {
		return false
	}
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(ruleID) == "" || strings.TrimSpace(entity) == "" {
		return false
	}
	return scope.TenantID == strings.TrimSpace(tenantID) &&
		scope.RuleID == strings.TrimSpace(ruleID) &&
		scope.Entity == strings.TrimSpace(entity)
}

func feedbackAdjustmentActive(adjustment candidateAdjustment, tenantID, ruleID, entity string, now time.Time) bool {
	return adjustment.Shadow && feedbackAppliesTo(adjustment.Scope, tenantID, ruleID, entity, now)
}
