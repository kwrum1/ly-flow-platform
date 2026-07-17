package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
)

const (
	controlHealthSchemaVersion = "lyflow.control_health.v1"
	controlHealthEventType     = "control.health"
	controlHealthHealthy       = "healthy"
	controlHealthDegraded      = "degraded"
	failOpen                   = "fail_open"
	failClosed                 = "fail_closed"
)

var ErrRuntimeMemoryBudget = errors.New("security-engine runtime memory budget exceeded")

type ControlHealthPublicationError struct {
	Stream string
	Cause  error
}

func (err *ControlHealthPublicationError) Error() string {
	return fmt.Sprintf("publish control health to %s: %v", err.Stream, err.Cause)
}

func (err *ControlHealthPublicationError) Unwrap() error {
	return err.Cause
}

type runtimeFailPolicy struct {
	Observation   string `json:"observation"`
	Integrity     string `json:"integrity"`
	Authorization string `json:"authorization"`
}

type runtimeLimits struct {
	QueueCapacity int   `json:"queue_capacity"`
	ReadBytes     int   `json:"read_bytes"`
	CPUBudgetMS   int64 `json:"cpu_budget_ms"`
	MemoryBytes   int   `json:"memory_bytes"`
	RestartBudget int   `json:"restart_budget"`
}

type ControlHealthPublicationSnapshot struct {
	Status     string `json:"status"`
	RetryCount uint64 `json:"retry_count"`
	LastError  string `json:"last_error"`
}

type RuntimeHealthSnapshot struct {
	SchemaVersion     string                           `json:"schema_version"`
	EventType         string                           `json:"event_type"`
	Runtime           string                           `json:"runtime"`
	Status            string                           `json:"status"`
	Reason            string                           `json:"reason"`
	PreventionEnabled bool                             `json:"prevention_enabled"`
	FailPolicy        runtimeFailPolicy                `json:"fail_policy"`
	Limits            runtimeLimits                    `json:"limits"`
	RestartCount      int                              `json:"restart_count"`
	WatchdogAt        time.Time                        `json:"watchdog_at"`
	Publication       ControlHealthPublicationSnapshot `json:"publication"`
}

type runtimeHealth struct {
	mu               sync.RWMutex
	limits           runtimeLimits
	status           string
	reason           string
	preventionActive bool
	restartCount     int
	watchdogAt       time.Time
	publication      ControlHealthPublicationSnapshot
}

func newRuntimeHealth(cfg config.Config) *runtimeHealth {
	return &runtimeHealth{
		limits: runtimeLimits{
			QueueCapacity: int(cfg.ReadCount), ReadBytes: cfg.MaxMessageBytes,
			CPUBudgetMS: cfg.CPUBudget.Milliseconds(), MemoryBytes: cfg.MemoryBudgetBytes, RestartBudget: cfg.RestartBudget,
		},
		status: controlHealthHealthy, preventionActive: true, watchdogAt: time.Now().UTC(),
		publication: ControlHealthPublicationSnapshot{Status: controlHealthHealthy},
	}
}

func (health *runtimeHealth) touchWatchdog() {
	health.mu.Lock()
	health.watchdogAt = time.Now().UTC()
	health.mu.Unlock()
}

func (health *runtimeHealth) checkWatchdog(maxAge time.Duration) bool {
	health.mu.Lock()
	defer health.mu.Unlock()
	if time.Since(health.watchdogAt) <= maxAge {
		return true
	}
	health.status = controlHealthDegraded
	health.reason = "watchdog_stale"
	health.watchdogAt = time.Now().UTC()
	return false
}

func (health *runtimeHealth) snapshot() RuntimeHealthSnapshot {
	health.mu.RLock()
	defer health.mu.RUnlock()
	return RuntimeHealthSnapshot{
		SchemaVersion: controlHealthSchemaVersion, EventType: controlHealthEventType, Runtime: "security-engine",
		Status: health.status, Reason: health.reason, PreventionEnabled: health.preventionActive,
		FailPolicy: runtimeFailPolicy{Observation: failOpen, Integrity: failClosed, Authorization: failClosed},
		Limits:     health.limits, RestartCount: health.restartCount, WatchdogAt: health.watchdogAt,
		Publication: health.publication,
	}
}

func (health *runtimeHealth) degrade(reason string, integrityFailure bool) RuntimeHealthSnapshot {
	health.mu.Lock()
	health.status = controlHealthDegraded
	health.reason = reason
	health.watchdogAt = time.Now().UTC()
	if integrityFailure {
		health.preventionActive = false
	}
	health.mu.Unlock()
	return health.snapshot()
}

func (health *runtimeHealth) recover() {
	health.mu.Lock()
	health.preventionActive = true
	if health.publication.Status == controlHealthDegraded {
		health.status = controlHealthDegraded
		health.reason = "control_health_delivery_unavailable"
	} else {
		health.status = controlHealthHealthy
		health.reason = ""
	}
	health.watchdogAt = time.Now().UTC()
	health.mu.Unlock()
}

func (health *runtimeHealth) recordPublicationFailure(err error) {
	health.mu.Lock()
	health.publication.Status = controlHealthDegraded
	health.publication.RetryCount++
	health.publication.LastError = err.Error()
	if health.preventionActive && (health.status == controlHealthHealthy || health.reason == "control_health_delivery_unavailable") {
		health.status = controlHealthDegraded
		health.reason = "control_health_delivery_unavailable"
	}
	health.mu.Unlock()
}

func (health *runtimeHealth) recordPublicationSuccess() {
	health.mu.Lock()
	wasDegraded := health.publication.Status == controlHealthDegraded
	health.publication.Status = controlHealthHealthy
	health.publication.LastError = ""
	if wasDegraded && health.preventionActive && health.reason == "control_health_delivery_unavailable" {
		health.status = controlHealthHealthy
		health.reason = ""
	}
	health.mu.Unlock()
}

func (health *runtimeHealth) recordWatchdogRestart() bool {
	health.mu.Lock()
	defer health.mu.Unlock()
	if health.restartCount >= health.limits.RestartBudget {
		health.status = controlHealthDegraded
		health.reason = "restart_budget_exhausted"
		health.preventionActive = false
		health.watchdogAt = time.Now().UTC()
		return false
	}
	health.restartCount++
	health.watchdogAt = time.Now().UTC()
	return true
}

func (e *Engine) RuntimeHealth() RuntimeHealthSnapshot {
	return e.health.snapshot()
}

func (e *Engine) RecordWatchdogRestart() bool {
	return e.health.recordWatchdogRestart()
}

func (e *Engine) VerifyIntegrity(ctx context.Context) (RuntimeHealthSnapshot, error) {
	state := e.state.Load()
	if state.manifest.ManifestPath == "" && e.cfg.RuleTrustRoot == "" && e.cfg.BundleRoot == "" {
		return e.RuntimeHealth(), nil
	}
	if state.manifest.ManifestPath == "" || e.cfg.RuleTrustRoot == "" || e.cfg.BundleRoot == "" {
		event := e.health.degrade("config_or_binary_integrity_failed", true)
		if err := e.publishControlHealth(ctx, event); err != nil {
			return e.RuntimeHealth(), errors.Join(ErrLifecycleManifest, err)
		}
		return event, ErrLifecycleManifest
	}
	bundle, manifest, err := LoadLifecycleBundle(state.manifest.ManifestPath, e.cfg.RuleTrustRoot, e.cfg.BundleRoot)
	if err != nil {
		event := e.health.degrade("config_or_binary_integrity_failed", true)
		integrityErr := fmt.Errorf("verify active lifecycle integrity: %w", err)
		if publishErr := e.publishControlHealth(ctx, event); publishErr != nil {
			return e.RuntimeHealth(), errors.Join(integrityErr, publishErr)
		}
		return event, integrityErr
	}
	if bundle.Digest != state.bundle.Digest || manifest.Revision != state.manifest.Revision {
		event := e.health.degrade("config_or_binary_integrity_failed", true)
		if err := e.publishControlHealth(ctx, event); err != nil {
			return e.RuntimeHealth(), errors.Join(ErrLifecycleManifest, err)
		}
		return event, ErrLifecycleManifest
	}
	e.health.recover()
	return e.RuntimeHealth(), nil
}

func (e *Engine) publishControlHealth(ctx context.Context, event RuntimeHealthSnapshot) error {
	if e.cfg.ControlHealthStream == "" {
		return nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		publishErr := &ControlHealthPublicationError{Stream: e.cfg.ControlHealthStream, Cause: fmt.Errorf("encode event: %w", err)}
		e.health.recordPublicationFailure(publishErr)
		return publishErr
	}
	policy := transport.RetryPolicy{MaxAttempts: 3, BaseDelay: 10 * time.Millisecond, MaxDelay: 40 * time.Millisecond}
	err = policy.Do(ctx, e.cfg.ControlHealthStream, func(attemptCtx context.Context) error {
		attemptErr := e.client.XAdd(attemptCtx, &redis.XAddArgs{Stream: e.cfg.ControlHealthStream, Values: map[string]any{"data": string(data)}}).Err()
		if attemptErr != nil {
			e.health.recordPublicationFailure(attemptErr)
		}
		return attemptErr
	}, nil)
	if err != nil {
		return &ControlHealthPublicationError{Stream: e.cfg.ControlHealthStream, Cause: err}
	}
	e.health.recordPublicationSuccess()
	return nil
}
