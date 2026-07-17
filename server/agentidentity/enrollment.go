package agentidentity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

type atomicEnrollmentStore interface {
	enrollAtomic(context.Context, [sha256.Size]byte, string, EnabledTransports, time.Time) (*Record, error)
}

func (m *Manager) Enroll(token, legacyCredential string, enabled EnabledTransports) (*Record, error) {
	return m.EnrollContext(context.Background(), token, legacyCredential, enabled)
}

func (m *Manager) EnrollContext(ctx context.Context, token, legacyCredential string, enabled EnabledTransports) (*Record, error) {
	m.tokenM.Lock()
	defer m.tokenM.Unlock()
	hash := sha256.Sum256([]byte(token))
	if m.atomicEnrollment != nil {
		return m.atomicEnrollment.enrollAtomic(ctx, hash, legacyCredential, enabled, m.now())
	}
	tokenRecord, err := m.usableToken(token, tokenEnrollment)
	if err != nil {
		return nil, err
	}
	record, err := NewLegacyRecord(tokenRecord.id, legacyCredential, enabled)
	if err != nil {
		return nil, err
	}
	if err := m.store.Put(record); err != nil {
		if m.tokenStore != nil {
			_ = m.tokenStore.restoreToken(hash)
		}
		return nil, fmt.Errorf("store enrollment: %w", err)
	}
	tokenRecord.used = true
	return record, nil
}
