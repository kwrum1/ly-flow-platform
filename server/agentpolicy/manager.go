package agentpolicy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type Manager struct {
	store    Store
	signer   trustroot.Signer
	verifier trustroot.Layout
	now      func() time.Time
}

type ManagerConfig struct {
	Store    Store
	Signer   trustroot.Signer
	Verifier trustroot.Layout
	Now      func() time.Time
}

func NewManager(config ManagerConfig) *Manager {
	return &Manager{store: config.Store, signer: config.Signer, verifier: config.Verifier, now: config.Now}
}

func (manager *Manager) EnsureDefault(ctx context.Context, owner, auditLink string) (SignedPolicy, error) {
	active, err := manager.store.Active(ctx)
	if err == nil {
		return active.Envelope, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return SignedPolicy{}, fmt.Errorf("load active policy: %w", err)
	}
	policy := DefaultPolicy(manager.now(), owner, auditLink)
	return manager.create(ctx, policy, StateActive)
}

func (manager *Manager) Create(ctx context.Context, policy Policy) (SignedPolicy, error) {
	return manager.create(ctx, policy, StateDraft)
}

func (manager *Manager) create(ctx context.Context, policy Policy, state State) (SignedPolicy, error) {
	now := manager.now()
	fingerprint := manager.signer.Fingerprint()
	payload, err := shared.CanonicalBytes(policy, fingerprint)
	if err != nil {
		return SignedPolicy{}, fmt.Errorf("canonicalize policy: %w", err)
	}
	envelope := SignedPolicy{Policy: policy, Signature: hex.EncodeToString(manager.signer.Sign(payload)), SignerFingerprint: fingerprint}
	latest, err := manager.store.Latest(ctx)
	if err == nil && policy.Version < latest.Envelope.Policy.Version {
		return SignedPolicy{}, ErrStaleVersion
	}
	if err == nil && policy.Version == latest.Envelope.Policy.Version {
		if reflect.DeepEqual(envelope, latest.Envelope) {
			return latest.Envelope, nil
		}
		return SignedPolicy{}, ErrSameVersionReplacement
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return SignedPolicy{}, fmt.Errorf("load latest policy: %w", err)
	}
	if err := validatePolicy(policy, now); err != nil {
		return SignedPolicy{}, err
	}
	if err := manager.verify(envelope); err != nil {
		return SignedPolicy{}, err
	}
	stored := PersistedPolicy{Envelope: envelope, State: state, CreatedAt: now, UpdatedAt: now}
	if err := manager.store.Create(ctx, stored, manager.event(policy, "created", "")); err != nil {
		return SignedPolicy{}, fmt.Errorf("persist policy: %w", err)
	}
	return envelope, nil
}

func (manager *Manager) StartCanary(ctx context.Context, version uint64) error {
	stored, err := manager.loadVerified(ctx, version)
	if err != nil {
		return err
	}
	if stored.State != StateDraft {
		return ErrInvalidTransition
	}
	previous := stored.State
	stored.State, stored.UpdatedAt = StateCanary, manager.now()
	return manager.store.Update(ctx, PolicyUpdate{Policy: stored, Expected: previous, Event: manager.event(stored.Envelope.Policy, "canary_started", "")})
}

func (manager *Manager) Assign(ctx context.Context, target AssignmentTarget, version uint64) (Assignment, error) {
	stored, err := manager.loadVerified(ctx, version)
	if err != nil {
		return Assignment{}, err
	}
	if stored.State != StateCanary && stored.State != StateActive {
		return Assignment{}, ErrInvalidTransition
	}
	if !stored.Envelope.Policy.ExpiresAt.After(manager.now()) {
		return Assignment{}, ErrExpired
	}
	if !matchesTarget(stored.Envelope.Policy.Selectors, target) {
		return Assignment{}, ErrSelectorMismatch
	}
	existing, existingErr := manager.store.Assignment(ctx, target.AgentID)
	if existingErr == nil && existing.Envelope.Policy.Version == version && existing.Envelope.Signature == stored.Envelope.Signature {
		return existing, nil
	}
	if existingErr != nil && !errors.Is(existingErr, ErrNotFound) {
		return Assignment{}, fmt.Errorf("load existing assignment: %w", existingErr)
	}
	assignment := Assignment{AgentID: target.AgentID, Envelope: stored.Envelope, AssignedAt: manager.now()}
	if err := manager.store.Assign(ctx, assignment, manager.event(stored.Envelope.Policy, "assigned", target.AgentID)); err != nil {
		return Assignment{}, fmt.Errorf("persist assignment: %w", err)
	}
	return assignment, nil
}

func (manager *Manager) AssignCurrent(ctx context.Context, target AssignmentTarget) (Assignment, error) {
	latest, latestErr := manager.store.Latest(ctx)
	if latestErr == nil && latest.State == StateCanary {
		if latest.Envelope.Policy.ExpiresAt.After(manager.now()) && matchesTarget(latest.Envelope.Policy.Selectors, target) {
			return manager.Assign(ctx, target, latest.Envelope.Policy.Version)
		}
		if !latest.Envelope.Policy.ExpiresAt.After(manager.now()) {
			if err := manager.Expire(ctx, latest.Envelope.Policy.Version); err != nil && !errors.Is(err, ErrInvalidTransition) {
				return Assignment{}, fmt.Errorf("expire canary policy: %w", err)
			}
		}
	}
	active, err := manager.store.Active(ctx)
	if err != nil {
		return Assignment{}, fmt.Errorf("load active policy: %w", err)
	}
	if !active.Envelope.Policy.ExpiresAt.After(manager.now()) {
		return Assignment{}, ErrExpired
	}
	return manager.Assign(ctx, target, active.Envelope.Policy.Version)
}

func (manager *Manager) Acknowledge(ctx context.Context, acknowledgement Acknowledgement) error {
	assignment, err := manager.store.Assignment(ctx, acknowledgement.AgentID)
	if err != nil {
		return fmt.Errorf("load assignment: %w", err)
	}
	if assignment.Envelope.Policy.Version != acknowledgement.Version || assignment.Envelope.Signature != acknowledgement.Signature {
		return ErrStaleVersion
	}
	if assignment.ACKVersion == acknowledgement.Version && assignment.ACKSignature == acknowledgement.Signature {
		return nil
	}
	assignment.ACKVersion, assignment.ACKSignature, assignment.ACKedAt = acknowledgement.Version, acknowledgement.Signature, manager.now()
	return manager.store.Acknowledge(ctx, assignment, manager.event(assignment.Envelope.Policy, "acknowledged", acknowledgement.AgentID))
}

func matchesTarget(selectors Selectors, target AssignmentTarget) bool {
	if len(selectors.AgentIDs) == 0 {
		return matchesLanguage(selectors.Languages, target.Capabilities.Languages)
	}
	for _, selected := range selectors.AgentIDs {
		if selected == target.AgentID {
			return matchesLanguage(selectors.Languages, target.Capabilities.Languages)
		}
	}
	return false
}

func matchesLanguage(selectors, capabilities []Language) bool {
	if len(selectors) == 0 {
		return true
	}
	for _, selected := range selectors {
		for _, declared := range capabilities {
			if selected == declared {
				return true
			}
		}
	}
	return false
}
