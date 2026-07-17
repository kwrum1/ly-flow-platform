package main

import (
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type xdrHealthStatus string

const (
	xdrHealthHealthy  xdrHealthStatus = "healthy"
	xdrHealthDegraded xdrHealthStatus = "degraded"
)

type xdrAlgorithmHealth struct {
	Algorithm            string          `json:"algorithm"`
	Status               xdrHealthStatus `json:"status"`
	Checkpoint           string          `json:"checkpoint,omitempty"`
	GraphChecksum        string          `json:"graph_checksum,omitempty"`
	LastPersistenceError string          `json:"last_persistence_error,omitempty"`
	UpdatedAt            time.Time       `json:"updated_at,omitempty"`
}

type xdrRuntimeHealth struct {
	Status               xdrHealthStatus               `json:"status"`
	LastPersistenceError string                        `json:"last_persistence_error,omitempty"`
	Algorithms           map[string]xdrAlgorithmHealth `json:"algorithms"`
	ReadAdapter          xdrAdapterHealth              `json:"read_adapter"`
}

type xdrHealthTracker struct {
	mu         sync.RWMutex
	algorithms map[models.AlgorithmIdentity]xdrAlgorithmHealth
}

func newXDRHealthTracker() *xdrHealthTracker {
	return &xdrHealthTracker{algorithms: map[models.AlgorithmIdentity]xdrAlgorithmHealth{}}
}

func (tracker *xdrHealthTracker) success(identity models.AlgorithmIdentity, checkpoint, checksum string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.algorithms[identity] = xdrAlgorithmHealth{Algorithm: identity.String(), Status: xdrHealthHealthy, Checkpoint: checkpoint, GraphChecksum: checksum, UpdatedAt: time.Now().UTC()}
}

func (tracker *xdrHealthTracker) restore(identity models.AlgorithmIdentity, checkpoint, checksum string, updatedAt time.Time) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.algorithms[identity] = xdrAlgorithmHealth{
		Algorithm: identity.String(), Status: xdrHealthHealthy, Checkpoint: checkpoint,
		GraphChecksum: checksum, UpdatedAt: updatedAt,
	}
}

func (tracker *xdrHealthTracker) failure(identity models.AlgorithmIdentity, err error) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	previous := tracker.algorithms[identity]
	previous.Algorithm = identity.String()
	previous.Status = xdrHealthDegraded
	previous.LastPersistenceError = err.Error()
	previous.UpdatedAt = time.Now().UTC()
	tracker.algorithms[identity] = previous
}

func (tracker *xdrHealthTracker) snapshot(adapter xdrAdapterHealth) xdrRuntimeHealth {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	status := xdrHealthHealthy
	lastError := ""
	algorithms := make(map[string]xdrAlgorithmHealth, len(tracker.algorithms))
	for identity, health := range tracker.algorithms {
		algorithms[identity.String()] = health
		if health.Status == xdrHealthDegraded {
			status = xdrHealthDegraded
			lastError = health.LastPersistenceError
		}
	}
	return xdrRuntimeHealth{Status: status, LastPersistenceError: lastError, Algorithms: algorithms, ReadAdapter: adapter}
}
