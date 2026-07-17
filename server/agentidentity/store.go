package agentidentity

import (
	"errors"
	"sync"
)

var ErrAgentNotFound = errors.New("agent identity: agent not found")

type Store interface {
	Put(*Record) error
	Get(AgentID) (*Record, error)
}

type MemoryStore struct {
	mu      sync.RWMutex
	records map[AgentID]*Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[AgentID]*Record)}
}

func (s *MemoryStore) Put(record *Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := record.ID()
	if existing, ok := s.records[id]; ok && existing != record {
		return ErrInvalidTransition
	}
	s.records[id] = record
	return nil
}

func (s *MemoryStore) Get(id AgentID) (*Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return record, nil
}
