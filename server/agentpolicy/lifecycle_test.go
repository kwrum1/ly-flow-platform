package agentpolicy

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

func TestPolicyLifecycle_monitor_canary_promotes_expires_and_rolls_back(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	ctx := context.Background()
	if _, err := harness.manager.EnsureDefault(ctx, "platform-owner", "audit://policy/default"); err != nil {
		t.Fatalf("ensure default policy: %v", err)
	}
	policy := harness.monitorPolicy(2)

	// When
	signed, err := harness.manager.Create(ctx, policy)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := harness.manager.StartCanary(ctx, policy.Version); err != nil {
		t.Fatalf("start canary: %v", err)
	}
	assignment, err := harness.manager.Assign(ctx, assignmentTarget("agent-canary", shared.LanguagePython), policy.Version)
	if err != nil {
		t.Fatalf("assign policy: %v", err)
	}
	if err := harness.manager.Acknowledge(ctx, Acknowledgement{AgentID: assignment.AgentID, Version: policy.Version, Signature: signed.Signature}); err != nil {
		t.Fatalf("acknowledge policy: %v", err)
	}
	if err := harness.manager.CompleteCanary(ctx, policy.Version, successfulCanary()); err != nil {
		t.Fatalf("complete canary: %v", err)
	}
	if err := harness.manager.Promote(ctx, policy.Version); err != nil {
		t.Fatalf("promote monitor policy: %v", err)
	}
	harness.now = policy.ExpiresAt.Add(time.Second)
	if err := harness.manager.Expire(ctx, policy.Version); err != nil {
		t.Fatalf("expire policy: %v", err)
	}
	if err := harness.manager.Rollback(ctx, policy.Version); err != nil {
		t.Fatalf("rollback policy: %v", err)
	}

	// Then
	current, err := harness.store.Active(ctx)
	if err != nil {
		t.Fatalf("load active policy: %v", err)
	}
	if current.Envelope.Policy.Version != 1 || current.State != StateActive {
		t.Fatalf("active policy = version %d state %s, want version 1 active", current.Envelope.Policy.Version, current.State)
	}
	rolledBack, err := harness.store.Get(ctx, policy.Version)
	if err != nil {
		t.Fatalf("load rolled back policy: %v", err)
	}
	if rolledBack.State != StateRolledBack {
		t.Fatalf("state = %s, want %s", rolledBack.State, StateRolledBack)
	}
}

func TestPolicyAssignment_rejects_bad_signature_and_stale_version(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	ctx := context.Background()
	if _, err := harness.manager.Create(ctx, harness.monitorPolicy(2)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	harness.store.mu.Lock()
	tampered := harness.store.policies[2]
	tampered.Envelope.Signature = "00"
	harness.store.policies[2] = tampered
	harness.store.mu.Unlock()

	// When
	_, signatureErr := harness.manager.Assign(ctx, assignmentTarget("agent-canary", shared.LanguagePython), 2)
	_, staleErr := harness.manager.Create(ctx, harness.monitorPolicy(1))

	// Then
	if !errors.Is(signatureErr, ErrSignature) {
		t.Fatalf("signature error = %v, want ErrSignature", signatureErr)
	}
	if !errors.Is(staleErr, ErrStaleVersion) {
		t.Fatalf("stale error = %v, want ErrStaleVersion", staleErr)
	}
}

func TestPolicyAssignment_enforces_languages_and_expired_canary_falls_back_to_active(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	ctx := context.Background()
	policy := harness.monitorPolicy(2)
	createCanaryForTest(t, harness, policy)

	// When
	_, mismatchErr := harness.manager.Assign(ctx, assignmentTarget("agent-canary", shared.LanguageJava), policy.Version)
	harness.now = policy.ExpiresAt.Add(time.Second)
	assignment, fallbackErr := harness.manager.AssignCurrent(ctx, assignmentTarget("agent-canary", shared.LanguagePython))

	// Then
	if !errors.Is(mismatchErr, ErrSelectorMismatch) {
		t.Fatalf("language mismatch error = %v", mismatchErr)
	}
	if fallbackErr != nil {
		t.Fatalf("assign active fallback: %v", fallbackErr)
	}
	if assignment.Envelope.Policy.Version != 1 {
		t.Fatalf("fallback version = %d, want active version 1", assignment.Envelope.Policy.Version)
	}
	expired, err := harness.store.Get(ctx, policy.Version)
	if err != nil || expired.State != StateExpired {
		t.Fatalf("expired canary = state %q error %v", expired.State, err)
	}
}

func TestPolicyCreate_same_version_allows_only_exact_signed_envelope(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	ctx := context.Background()
	policy := harness.monitorPolicy(2)
	first, err := harness.manager.Create(ctx, policy)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	harness.now = policy.ExpiresAt.Add(time.Second)

	// When
	retry, retryErr := harness.manager.Create(ctx, policy)
	policy.AuditLink = "audit://different"
	_, replacementErr := harness.manager.Create(ctx, policy)

	// Then
	if retryErr != nil || !reflect.DeepEqual(retry, first) {
		t.Fatalf("exact retry = %#v error %v, want %#v", retry, retryErr, first)
	}
	if !errors.Is(replacementErr, ErrSameVersionReplacement) {
		t.Fatalf("replacement error = %v", replacementErr)
	}
}

func TestPolicySignature_binds_and_verifies_signer_fingerprint(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	ctx := context.Background()
	signed, err := harness.manager.Create(ctx, harness.monitorPolicy(2))
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	harness.store.mu.Lock()
	tampered := harness.store.policies[2]
	tampered.Envelope.SignerFingerprint = strings.Repeat("0", 64)
	harness.store.policies[2] = tampered
	harness.store.mu.Unlock()

	// When
	_, verifyErr := harness.manager.Assign(ctx, assignmentTarget("agent-canary", shared.LanguagePython), signed.Policy.Version)

	// Then
	if !errors.Is(verifyErr, ErrSignature) {
		t.Fatalf("fingerprint verification error = %v, want ErrSignature", verifyErr)
	}
}
