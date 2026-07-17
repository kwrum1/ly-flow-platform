package agentidentity

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

type failOnceStore struct {
	Store
	failed bool
}

func (s *failOnceStore) Put(record *Record) error {
	if !s.failed {
		s.failed = true
		return errors.New("interrupted persistence")
	}
	return s.Store.Put(record)
}

func TestEnrollmentTokenRemainsUsableAfterPersistenceInterruption(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := &failOnceStore{Store: NewMemoryStore()}
	manager := NewManager(store, func() time.Time { return now })
	token, err := manager.IssueEnrollmentToken("agent-interrupted", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// When
	_, firstErr := manager.Enroll(token, "legacy", EnabledTransports{HTTP: true})
	_, retryErr := manager.Enroll(token, "legacy", EnabledTransports{HTTP: true})

	// Then
	if firstErr == nil {
		t.Fatal("first enrollment succeeded despite interrupted persistence")
	}
	if retryErr != nil {
		t.Fatalf("retry after interruption: %v", retryErr)
	}
}

type atomicFailOnceStore struct {
	mu         sync.Mutex
	tokens     map[[sha256.Size]byte]tokenRecord
	records    map[AgentID]*Record
	failed     bool
	atomicCall bool
}

func newAtomicFailOnceStore() *atomicFailOnceStore {
	return &atomicFailOnceStore{
		tokens:  make(map[[sha256.Size]byte]tokenRecord),
		records: make(map[AgentID]*Record),
	}
}

func (s *atomicFailOnceStore) Put(*Record) error { return errors.New("non-atomic put interrupted") }

func (s *atomicFailOnceStore) Get(id AgentID) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return record, nil
}

func (s *atomicFailOnceStore) putToken(hash [sha256.Size]byte, record tokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[hash] = record
	return nil
}

func (s *atomicFailOnceStore) consumeToken(hash [sha256.Size]byte, purpose tokenPurpose, now time.Time) (tokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tokens[hash]
	if !ok || record.purpose != purpose {
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

func (*atomicFailOnceStore) restoreToken([sha256.Size]byte) error {
	return errors.New("restore interrupted")
}

func (s *atomicFailOnceStore) enrollAtomic(_ context.Context, hash [sha256.Size]byte, credential string, enabled EnabledTransports, now time.Time) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.atomicCall = true
	token, ok := s.tokens[hash]
	if !ok || token.purpose != tokenEnrollment {
		return nil, ErrTokenUnknown
	}
	if token.used {
		return nil, ErrTokenUsed
	}
	if now.After(token.expiresAt) {
		return nil, ErrTokenExpired
	}
	if !s.failed {
		s.failed = true
		return nil, errors.New("identity persistence interrupted after token update")
	}
	record, err := NewLegacyRecord(token.id, credential, enabled)
	if err != nil {
		return nil, err
	}
	token.used = true
	s.tokens[hash] = token
	s.records[token.id] = record
	return record, nil
}

func TestPersistentEnrollmentIsAtomicAndRetryableWhenStoresMatch(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := newAtomicFailOnceStore()
	manager := NewPersistentManager(store, store, func() time.Time { return now })
	token, err := manager.IssueEnrollmentToken("agent-atomic", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// When
	_, firstErr := manager.EnrollContext(context.Background(), token, "legacy", EnabledTransports{HTTP: true})
	_, retryErr := manager.EnrollContext(context.Background(), token, "legacy", EnabledTransports{HTTP: true})

	// Then
	if firstErr == nil {
		t.Fatal("first enrollment succeeded despite interrupted identity persistence")
	}
	if retryErr != nil {
		t.Fatalf("retry after atomic rollback: %v", retryErr)
	}
	if !store.atomicCall {
		t.Fatal("matching persistent stores did not use atomic enrollment")
	}
}

func TestAgentIDRejectsMalformedIdentity(t *testing.T) {
	// When
	_, err := NewAgentID("../../host name")

	// Then
	if !errors.Is(err, ErrInvalidAgentID) {
		t.Fatalf("malformed identity error = %v", err)
	}
}
