package agentidentity

import (
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

type sharedTokenStore struct {
	mu     sync.Mutex
	tokens map[[sha256.Size]byte]tokenRecord
}

func newSharedTokenStore() *sharedTokenStore {
	return &sharedTokenStore{tokens: make(map[[sha256.Size]byte]tokenRecord)}
}

func (s *sharedTokenStore) putToken(hash [sha256.Size]byte, record tokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[hash]; !exists {
		s.tokens[hash] = record
	}
	return nil
}

func (s *sharedTokenStore) consumeToken(hash [sha256.Size]byte, purpose tokenPurpose, now time.Time) (tokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.tokens[hash]
	if !exists || record.purpose != purpose {
		return tokenRecord{}, ErrTokenUnknown
	}
	if record.used {
		return tokenRecord{}, ErrTokenUsed
	}
	if now.After(record.expiresAt) {
		return tokenRecord{}, ErrTokenExpired
	}
	record.used = true
	s.tokens[hash] = record
	return record, nil
}

func (s *sharedTokenStore) restoreToken(hash [sha256.Size]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.tokens[hash]
	record.used = false
	s.tokens[hash] = record
	return nil
}

func TestIdentityStateSurvivesManagerRestartAcrossTransports(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	first := NewManager(store, func() time.Time { return now })
	id, err := NewAgentID("agent-restart")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := NewLegacyRecord(id, "legacy", EnabledTransports{HTTP: true, GRPC: true})
	if err != nil {
		t.Fatalf("legacy record: %v", err)
	}
	if err := first.Store(record); err != nil {
		t.Fatalf("store record: %v", err)
	}
	if err := first.Transition(id, StateLegacyVerified, record.Version()); err != nil {
		t.Fatalf("legacy verified: %v", err)
	}
	if err := first.Transition(id, StateHashMigrated, record.Version()); err != nil {
		t.Fatalf("hash migrated: %v", err)
	}
	if err := first.BeginRotation(id, "new", time.Hour, record.Version()); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}

	// When
	second := NewManager(store, func() time.Time { return now })
	httpErr := second.Authenticate(id.String(), "new", TransportHTTP)
	grpcErr := second.Authenticate(id.String(), "new", TransportGRPC)

	// Then
	if httpErr != nil || grpcErr != nil {
		t.Fatalf("restarted transport authentication: http=%v grpc=%v", httpErr, grpcErr)
	}
	reloaded, err := store.Get(id)
	if err != nil {
		t.Fatalf("reload record: %v", err)
	}
	if reloaded.State() != StateConfirmed {
		t.Fatalf("reloaded state = %s", reloaded.State())
	}
}

func TestEnrollmentTokenReplayRejectedAcrossManagerRestart(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	records := NewMemoryStore()
	tokens := newSharedTokenStore()
	first := NewPersistentManager(records, tokens, func() time.Time { return now })
	token, err := first.IssueEnrollmentToken("agent-token-restart", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := first.Enroll(token, "legacy", EnabledTransports{HTTP: true}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// When
	second := NewPersistentManager(records, tokens, func() time.Time { return now })
	_, replayErr := second.Enroll(token, "other", EnabledTransports{GRPC: true})

	// Then
	if replayErr != ErrTokenUsed {
		t.Fatalf("replayed token error = %v", replayErr)
	}
}
