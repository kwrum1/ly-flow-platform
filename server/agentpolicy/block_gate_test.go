package agentpolicy

import (
	"context"
	"errors"
	"testing"
)

func TestBlockPromotion_rejects_missing_ack_failed_canary_and_replay_metrics(t *testing.T) {
	tests := []struct {
		name      string
		prepare   func(*testing.T, *policyHarness, uint64)
		wantError error
	}{
		{
			name: "missing acknowledgement",
			prepare: func(t *testing.T, harness *policyHarness, version uint64) {
				t.Helper()
				completeCanaryForTest(t, harness, version, successfulCanary())
			},
			wantError: ErrMissingACK,
		},
		{
			name: "failed canary",
			prepare: func(t *testing.T, harness *policyHarness, version uint64) {
				t.Helper()
				ackCanaryForTest(t, harness, version)
				completeCanaryForTest(t, harness, version, CanaryObservation{Succeeded: false, FailureReason: "synthetic probe failed"})
			},
			wantError: ErrCanaryFailed,
		},
		{
			name: "missing replay metrics",
			prepare: func(t *testing.T, harness *policyHarness, version uint64) {
				t.Helper()
				ackCanaryForTest(t, harness, version)
				completeCanaryForTest(t, harness, version, CanaryObservation{Succeeded: true})
			},
			wantError: ErrReplayMetricsRequired,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			harness := newPolicyHarness(t)
			version := uint64(index + 2)
			createCanaryForTest(t, harness, harness.blockPolicy(version))
			test.prepare(t, harness, version)

			// When
			err := harness.manager.Promote(context.Background(), version)

			// Then
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			stored, getErr := harness.store.Get(context.Background(), version)
			if getErr != nil {
				t.Fatalf("load policy: %v", getErr)
			}
			if stored.State == StateActive {
				t.Fatal("rejected block policy became active")
			}
		})
	}
}

func TestBlockPromotion_stays_disabled_without_operator_opt_in(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	policy := harness.blockPolicy(2)
	createCanaryForTest(t, harness, policy)
	ackCanaryForTest(t, harness, policy.Version)
	completeCanaryForTest(t, harness, policy.Version, successfulCanary())

	// When
	err := harness.manager.Promote(context.Background(), policy.Version)

	// Then
	if !errors.Is(err, ErrProductionBlockDisabled) {
		t.Fatalf("error = %v, want ErrProductionBlockDisabled", err)
	}
}

func TestBlockPromotion_activates_after_opt_in_and_all_safety_gates(t *testing.T) {
	// Given
	harness := newPolicyHarnessWithBlockOptIn(t)
	policy := harness.blockPolicy(2)
	createCanaryForTest(t, harness, policy)
	ackCanaryForTest(t, harness, policy.Version)
	completeCanaryForTest(t, harness, policy.Version, successfulCanary())

	// When
	err := harness.manager.Promote(context.Background(), policy.Version)

	// Then
	if err != nil {
		t.Fatalf("promote block policy: %v", err)
	}
	state, stateErr := harness.manager.PolicyState(context.Background(), policy.Version)
	if stateErr != nil {
		t.Fatalf("load policy state: %v", stateErr)
	}
	if state != StateActive {
		t.Fatalf("state = %q, want active", state)
	}
}

func TestBlockPolicy_requires_explicit_owner_and_rollback(t *testing.T) {
	// Given
	harness := newPolicyHarness(t)
	missingOwner := harness.blockPolicy(2)
	missingOwner.Owner = ""
	missingRollback := harness.blockPolicy(3)
	missingRollback.Rollback = RollbackPolicy{}

	// When
	_, ownerErr := harness.manager.Create(context.Background(), missingOwner)
	_, rollbackErr := harness.manager.Create(context.Background(), missingRollback)

	// Then
	if !errors.Is(ownerErr, ErrOwnerRequired) {
		t.Fatalf("owner error = %v, want ErrOwnerRequired", ownerErr)
	}
	if !errors.Is(rollbackErr, ErrRollbackRequired) {
		t.Fatalf("rollback error = %v, want ErrRollbackRequired", rollbackErr)
	}
}
