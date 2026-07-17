package agentidentity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type tokenPurpose string

const (
	tokenEnrollment tokenPurpose = "enrollment"
	tokenRecovery   tokenPurpose = "recovery"
)

type tokenRecord struct {
	id        AgentID
	purpose   tokenPurpose
	expiresAt time.Time
	used      bool
}

type Manager struct {
	store            Store
	now              func() time.Time
	tokenM           sync.Mutex
	tokens           map[[sha256.Size]byte]*tokenRecord
	tokenStore       tokenStore
	atomicEnrollment atomicEnrollmentStore
}

func NewManager(store Store, now func() time.Time) *Manager {
	return &Manager{store: store, now: now, tokens: make(map[[sha256.Size]byte]*tokenRecord)}
}

func NewPersistentManager(store Store, tokens tokenStore, now func() time.Time) *Manager {
	manager := &Manager{store: store, now: now, tokenStore: tokens, tokens: make(map[[sha256.Size]byte]*tokenRecord)}
	recordStore, recordStoreOK := store.(atomicEnrollmentStore)
	tokenStore, tokenStoreOK := tokens.(atomicEnrollmentStore)
	if recordStoreOK && tokenStoreOK && recordStore == tokenStore {
		manager.atomicEnrollment = recordStore
	}
	return manager
}

func (m *Manager) Store(record *Record) error { return m.store.Put(record) }

func (m *Manager) Status(id AgentID) (State, uint64, error) {
	record, err := m.store.Get(id)
	if err != nil {
		return "", 0, err
	}
	return record.State(), record.Version(), nil
}

func (m *Manager) IssueEnrollmentToken(rawID string, ttl time.Duration) (string, error) {
	id, err := NewAgentID(rawID)
	if err != nil {
		return "", err
	}
	return m.issueToken(id, tokenEnrollment, ttl)
}

func (m *Manager) RegisterEnrollmentToken(rawID, token string, ttl time.Duration) error {
	id, err := NewAgentID(rawID)
	if err != nil {
		return err
	}
	if token == "" || ttl <= 0 {
		return ErrTokenExpired
	}
	hash := sha256.Sum256([]byte(token))
	if m.tokenStore != nil {
		return m.tokenStore.putToken(hash, tokenRecord{id: id, purpose: tokenEnrollment, expiresAt: m.now().Add(ttl)})
	}
	m.tokenM.Lock()
	m.tokens[hash] = &tokenRecord{id: id, purpose: tokenEnrollment, expiresAt: m.now().Add(ttl)}
	m.tokenM.Unlock()
	return nil
}

func (m *Manager) IssueRecoveryToken(id AgentID, ttl time.Duration) (string, error) {
	record, err := m.store.Get(id)
	if err != nil {
		return "", err
	}
	if record.State() != StateLegacyRetired {
		return "", ErrInvalidTransition
	}
	return m.issueToken(id, tokenRecovery, ttl)
}

func (m *Manager) Recover(token, credential string) (*Record, error) {
	m.tokenM.Lock()
	defer m.tokenM.Unlock()
	tokenRecord, err := m.usableToken(token, tokenRecovery)
	if err != nil {
		return nil, err
	}
	record, err := m.store.Get(tokenRecord.id)
	if err != nil {
		return nil, err
	}
	if err := record.recover(credential); err != nil {
		return nil, err
	}
	if err := m.store.Put(record); err != nil {
		if m.tokenStore != nil {
			_ = m.tokenStore.restoreToken(sha256.Sum256([]byte(token)))
		}
		return nil, fmt.Errorf("store recovery: %w", err)
	}
	tokenRecord.used = true
	return record, nil
}

func (m *Manager) RetireLegacy(id AgentID, expectedVersion uint64) error {
	record, err := m.store.Get(id)
	if err != nil {
		return err
	}
	if err := record.Transition(StateLegacyRetired, expectedVersion); err != nil {
		return err
	}
	return m.store.Put(record)
}

func (m *Manager) Transition(id AgentID, next State, expectedVersion uint64) error {
	record, err := m.store.Get(id)
	if err != nil {
		return err
	}
	if err := record.Transition(next, expectedVersion); err != nil {
		return err
	}
	return m.store.Put(record)
}

func (m *Manager) BeginRotation(id AgentID, credential string, overlap time.Duration, expectedVersion uint64) error {
	record, err := m.store.Get(id)
	if err != nil {
		return err
	}
	if err := record.BeginRotation(credential, overlap, m.now(), expectedVersion); err != nil {
		return err
	}
	return m.store.Put(record)
}

func (m *Manager) Revoke(id AgentID, expectedVersion uint64) error {
	record, err := m.store.Get(id)
	if err != nil {
		return err
	}
	if err := record.Revoke(expectedVersion); err != nil {
		return err
	}
	return m.store.Put(record)
}

func (m *Manager) Rollback(id AgentID, expectedVersion uint64) error {
	record, err := m.store.Get(id)
	if err != nil {
		return err
	}
	if err := record.Rollback(expectedVersion); err != nil {
		return err
	}
	return m.store.Put(record)
}

func (m *Manager) Authenticate(rawID, credential string, transport Transport) error {
	id, err := NewAgentID(rawID)
	if err != nil {
		return err
	}
	record, err := m.store.Get(id)
	if err != nil {
		return err
	}
	previousVersion := record.Version()
	if err := record.Authenticate(credential, transport, m.now()); err != nil {
		return err
	}
	if record.Version() == previousVersion {
		return nil
	}
	return m.store.Put(record)
}

func (m *Manager) issueToken(id AgentID, purpose tokenPurpose, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", ErrTokenExpired
	}
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(plain)
	hash := sha256.Sum256([]byte(token))
	record := tokenRecord{id: id, purpose: purpose, expiresAt: m.now().Add(ttl)}
	if m.tokenStore != nil {
		if err := m.tokenStore.putToken(hash, record); err != nil {
			return "", err
		}
		return token, nil
	}
	m.tokenM.Lock()
	m.tokens[hash] = &record
	m.tokenM.Unlock()
	return token, nil
}

func (m *Manager) usableToken(token string, purpose tokenPurpose) (*tokenRecord, error) {
	hash := sha256.Sum256([]byte(token))
	if m.tokenStore != nil {
		record, err := m.tokenStore.consumeToken(hash, purpose, m.now())
		if err != nil {
			return nil, err
		}
		return &record, nil
	}
	record, ok := m.tokens[hash]
	if !ok || record.purpose != purpose {
		return nil, ErrTokenUnknown
	}
	if record.used {
		return nil, ErrTokenUsed
	}
	if m.now().After(record.expiresAt) {
		return nil, ErrTokenExpired
	}
	return record, nil
}
