package agentpolicy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

func (manager *Manager) CompleteCanary(ctx context.Context, version uint64, observation CanaryObservation) error {
	stored, err := manager.loadVerified(ctx, version)
	if err != nil {
		return err
	}
	if stored.State != StateCanary {
		return ErrInvalidTransition
	}
	stored.Canary, stored.UpdatedAt = &observation, manager.now()
	return manager.store.Update(ctx, PolicyUpdate{Policy: stored, Expected: StateCanary, Event: manager.event(stored.Envelope.Policy, "canary_completed", observation.FailureReason)})
}

func (manager *Manager) Promote(ctx context.Context, version uint64) error {
	stored, err := manager.loadVerified(ctx, version)
	if err != nil {
		return err
	}
	policy := stored.Envelope.Policy
	if stored.State != StateCanary || !policy.ExpiresAt.After(manager.now()) {
		return ErrInvalidTransition
	}
	acks, err := manager.store.ACKCount(ctx, version)
	if err != nil {
		return fmt.Errorf("count acknowledgements: %w", err)
	}
	if acks < policy.Canary.RequiredACKs {
		return ErrMissingACK
	}
	if stored.Canary == nil || !stored.Canary.Succeeded {
		return ErrCanaryFailed
	}
	if policy.Mode == ModeBlock {
		if stored.Canary.Replay == nil || stored.Canary.Replay.SampleCount < policy.Limits.ReplayMinSamples || stored.Canary.Replay.FalsePositiveRate > policy.Limits.ReplayMaxFalsePositiveRate {
			return ErrReplayMetricsRequired
		}
		if policy.Owner == "" {
			return ErrOwnerRequired
		}
		if policy.Rollback.TargetVersion == 0 || !policy.Rollback.Deadline.After(manager.now()) {
			return ErrRollbackRequired
		}
		target, targetErr := manager.loadVerified(ctx, policy.Rollback.TargetVersion)
		if targetErr != nil || target.Envelope.Policy.Mode != ModeMonitor {
			return ErrRollbackRequired
		}
		return ErrProductionBlockDisabled
	}
	stored.State, stored.UpdatedAt = StateActive, manager.now()
	return manager.store.Promote(ctx, stored, manager.event(policy, "promoted", "monitor-only"))
}

func (manager *Manager) Expire(ctx context.Context, version uint64) error {
	stored, err := manager.loadVerified(ctx, version)
	if err != nil {
		return err
	}
	if manager.now().Before(stored.Envelope.Policy.ExpiresAt) {
		return ErrInvalidTransition
	}
	previous := stored.State
	stored.State, stored.UpdatedAt = StateExpired, manager.now()
	return manager.store.Update(ctx, PolicyUpdate{Policy: stored, Expected: previous, Event: manager.event(stored.Envelope.Policy, "expired", "")})
}

func (manager *Manager) Rollback(ctx context.Context, version uint64) error {
	current, err := manager.loadVerified(ctx, version)
	if err != nil {
		return err
	}
	rollback := current.Envelope.Policy.Rollback
	if rollback.TargetVersion == 0 || manager.now().After(rollback.Deadline) {
		return ErrRollbackRequired
	}
	target, err := manager.loadVerified(ctx, rollback.TargetVersion)
	if err != nil {
		return fmt.Errorf("load rollback target: %w", err)
	}
	if target.Envelope.Policy.Mode != ModeMonitor {
		return ErrProductionBlockDisabled
	}
	current.State, current.UpdatedAt = StateRolledBack, manager.now()
	target.State, target.UpdatedAt = StateActive, manager.now()
	return manager.store.Rollback(ctx, RollbackChange{Current: current, Target: target, Event: manager.event(current.Envelope.Policy, "rolled_back", fmt.Sprintf("target=%d", rollback.TargetVersion))})
}

func (manager *Manager) loadVerified(ctx context.Context, version uint64) (PersistedPolicy, error) {
	stored, err := manager.store.Get(ctx, version)
	if err != nil {
		return PersistedPolicy{}, err
	}
	if err := manager.verify(stored.Envelope); err != nil {
		return PersistedPolicy{}, err
	}
	return stored, nil
}

func (manager *Manager) verify(envelope SignedPolicy) error {
	if envelope.SignerFingerprint == "" {
		return ErrSignature
	}
	payload, err := shared.CanonicalBytes(envelope.Policy, envelope.SignerFingerprint)
	if err != nil {
		return fmt.Errorf("canonicalize policy: %w", err)
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil {
		return ErrSignature
	}
	if err := manager.verifier.VerifyAttributed(trustroot.PolicyRoot, payload, signature, envelope.SignerFingerprint); err != nil {
		if errors.Is(err, trustroot.ErrSignature) || errors.Is(err, trustroot.ErrRootRevoked) {
			return ErrSignature
		}
		return fmt.Errorf("verify policy root: %w", err)
	}
	return nil
}

func (manager *Manager) event(policy Policy, eventType, detail string) AuditEvent {
	return AuditEvent{Version: policy.Version, Type: eventType, AuditLink: policy.AuditLink, Detail: detail, OccurredAt: manager.now()}
}
