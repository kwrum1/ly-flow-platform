package agentpolicy

import (
	"context"
	"fmt"
	"sync"
)

type MemoryStore struct {
	mu          sync.RWMutex
	policies    map[uint64]PersistedPolicy
	assignments map[string]Assignment
	events      []AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{policies: make(map[uint64]PersistedPolicy), assignments: make(map[string]Assignment)}
}

func (store *MemoryStore) Create(_ context.Context, policy PersistedPolicy, event AuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	version := policy.Envelope.Policy.Version
	if _, exists := store.policies[version]; exists {
		return ErrStaleVersion
	}
	store.policies[version] = clonePolicy(policy)
	store.events = append(store.events, event)
	return nil
}

func (store *MemoryStore) Get(_ context.Context, version uint64) (PersistedPolicy, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	policy, exists := store.policies[version]
	if !exists {
		return PersistedPolicy{}, ErrNotFound
	}
	return clonePolicy(policy), nil
}

func (store *MemoryStore) Latest(_ context.Context) (PersistedPolicy, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	var latest PersistedPolicy
	for version, policy := range store.policies {
		if version > latest.Envelope.Policy.Version {
			latest = policy
		}
	}
	if latest.Envelope.Policy.Version == 0 {
		return PersistedPolicy{}, ErrNotFound
	}
	return clonePolicy(latest), nil
}

func (store *MemoryStore) Active(_ context.Context) (PersistedPolicy, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	for _, policy := range store.policies {
		if policy.State == StateActive {
			return clonePolicy(policy), nil
		}
	}
	return PersistedPolicy{}, ErrNotFound
}

func (store *MemoryStore) Update(_ context.Context, update PolicyUpdate) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	version := update.Policy.Envelope.Policy.Version
	current, exists := store.policies[version]
	if !exists {
		return ErrNotFound
	}
	if current.State != update.Expected {
		return ErrInvalidTransition
	}
	store.policies[version] = clonePolicy(update.Policy)
	store.events = append(store.events, update.Event)
	return nil
}

func (store *MemoryStore) Promote(_ context.Context, candidate PersistedPolicy, event AuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	version := candidate.Envelope.Policy.Version
	current, exists := store.policies[version]
	if !exists || current.State != StateCanary {
		return ErrInvalidTransition
	}
	for existingVersion, policy := range store.policies {
		if policy.State == StateActive {
			policy.State = StateSuperseded
			policy.UpdatedAt = candidate.UpdatedAt
			store.policies[existingVersion] = policy
		}
	}
	store.policies[version] = clonePolicy(candidate)
	store.events = append(store.events, event)
	return nil
}

func (store *MemoryStore) Rollback(_ context.Context, change RollbackChange) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	currentVersion := change.Current.Envelope.Policy.Version
	targetVersion := change.Target.Envelope.Policy.Version
	if _, exists := store.policies[currentVersion]; !exists {
		return ErrNotFound
	}
	if _, exists := store.policies[targetVersion]; !exists {
		return ErrNotFound
	}
	store.policies[currentVersion] = clonePolicy(change.Current)
	store.policies[targetVersion] = clonePolicy(change.Target)
	store.events = append(store.events, change.Event)
	return nil
}

func (store *MemoryStore) Assign(_ context.Context, assignment Assignment, event AuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.assignments[assignment.AgentID] = assignment
	store.events = append(store.events, event)
	return nil
}

func (store *MemoryStore) Assignment(_ context.Context, agentID string) (Assignment, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	assignment, exists := store.assignments[agentID]
	if !exists {
		return Assignment{}, ErrNotFound
	}
	return assignment, nil
}

func (store *MemoryStore) Acknowledge(_ context.Context, assignment Assignment, event AuditEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.assignments[assignment.AgentID]
	if !exists {
		return ErrNotFound
	}
	if current.Envelope.Policy.Version != assignment.ACKVersion || current.Envelope.Signature != assignment.ACKSignature {
		return fmt.Errorf("assignment changed before acknowledgement: %w", ErrStaleVersion)
	}
	store.assignments[assignment.AgentID] = assignment
	store.events = append(store.events, event)
	return nil
}

func (store *MemoryStore) ACKCount(_ context.Context, version uint64) (int, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	count := 0
	for _, assignment := range store.assignments {
		if assignment.ACKVersion == version {
			count++
		}
	}
	return count, nil
}

func clonePolicy(policy PersistedPolicy) PersistedPolicy {
	policy.Envelope.Policy.Selectors.AgentIDs = append([]string(nil), policy.Envelope.Policy.Selectors.AgentIDs...)
	policy.Envelope.Policy.Selectors.Languages = append(policy.Envelope.Policy.Selectors.Languages[:0:0], policy.Envelope.Policy.Selectors.Languages...)
	if policy.Canary != nil {
		canary := *policy.Canary
		if policy.Canary.Replay != nil {
			replay := *policy.Canary.Replay
			canary.Replay = &replay
		}
		policy.Canary = &canary
	}
	return policy
}
