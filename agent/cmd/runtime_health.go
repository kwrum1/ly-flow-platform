package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	controlHealthSchemaVersion = "lyflow.control_health.v1"
	controlHealthEventType     = "control.health"
	controlHealthHealthy       = "healthy"
	controlHealthDegraded      = "degraded"
	failOpen                   = "fail_open"
	failClosed                 = "fail_closed"
)

var (
	errRuntimeReadLimit   = errors.New("runtime read budget exceeded")
	errRuntimeCPUBudget   = errors.New("runtime CPU budget exceeded")
	errRuntimeMemoryLimit = errors.New("runtime memory budget exceeded")
)

type RuntimeLimits struct {
	QueueCapacity int           `json:"queue_capacity"`
	ReadBytes     int           `json:"read_bytes"`
	CPUBudget     time.Duration `json:"-"`
	CPUBudgetMS   int64         `json:"cpu_budget_ms"`
	MemoryBytes   int           `json:"memory_bytes"`
	RestartBudget int           `json:"restart_budget"`
}

type runtimeFailPolicy struct {
	Observation   string `json:"observation"`
	Integrity     string `json:"integrity"`
	Authorization string `json:"authorization"`
}

type runtimeControlHealthSnapshot struct {
	SchemaVersion     string                           `json:"schema_version"`
	EventType         string                           `json:"event_type"`
	Runtime           string                           `json:"runtime"`
	Status            string                           `json:"status"`
	Reason            string                           `json:"reason"`
	PreventionEnabled bool                             `json:"prevention_enabled"`
	FailPolicy        runtimeFailPolicy                `json:"fail_policy"`
	Limits            RuntimeLimits                    `json:"limits"`
	RestartCount      int                              `json:"restart_count"`
	WatchdogAt        time.Time                        `json:"watchdog_at"`
	Publication       controlHealthPublicationSnapshot `json:"publication"`
}

type controlHealthPublicationSnapshot struct {
	Status     string `json:"status"`
	RetryCount uint64 `json:"retry_count"`
	LastError  string `json:"last_error"`
}

type controlHealthPublicationError struct {
	Cause error
}

func (err *controlHealthPublicationError) Error() string {
	return fmt.Sprintf("publish control health: %v", err.Cause)
}

func (err *controlHealthPublicationError) Unwrap() error {
	return err.Cause
}

type runtimeControlHealth struct {
	mu               sync.RWMutex
	runtime          string
	limits           RuntimeLimits
	now              func() time.Time
	status           string
	reason           string
	preventionActive bool
	restartCount     int
	watchdogAt       time.Time
	publication      controlHealthPublicationSnapshot
}

type runtimeHealthContextKey struct{}

func withRuntimeHealth(ctx context.Context, health *runtimeControlHealth) context.Context {
	return context.WithValue(ctx, runtimeHealthContextKey{}, health)
}

func (a *Agent) runtimeHealthFor(ctx context.Context) *runtimeControlHealth {
	if health, ok := ctx.Value(runtimeHealthContextKey{}).(*runtimeControlHealth); ok && health != nil {
		return health
	}
	return a.runtimeHealth
}

func agentRuntimeLimits() RuntimeLimits {
	return RuntimeLimits{
		QueueCapacity: 128,
		ReadBytes:     1 << 20,
		CPUBudget:     100 * time.Millisecond,
		CPUBudgetMS:   100,
		MemoryBytes:   256 << 10,
		RestartBudget: 3,
	}
}

func newRuntimeControlHealth(runtime string, limits RuntimeLimits, now func() time.Time) *runtimeControlHealth {
	return &runtimeControlHealth{
		runtime: runtime, limits: limits, now: now, status: controlHealthHealthy,
		watchdogAt: now().UTC(), publication: controlHealthPublicationSnapshot{Status: controlHealthHealthy},
	}
}

func (health *runtimeControlHealth) Snapshot() runtimeControlHealthSnapshot {
	health.mu.RLock()
	defer health.mu.RUnlock()
	return runtimeControlHealthSnapshot{
		SchemaVersion: controlHealthSchemaVersion, EventType: controlHealthEventType, Runtime: health.runtime,
		Status: health.status, Reason: health.reason, PreventionEnabled: health.preventionActive,
		FailPolicy: runtimeFailPolicy{Observation: failOpen, Integrity: failClosed, Authorization: failClosed},
		Limits:     health.limits, RestartCount: health.restartCount, WatchdogAt: health.watchdogAt,
		Publication: health.publication,
	}
}

func (health *runtimeControlHealth) setPreventionEnabled(enabled bool) {
	health.mu.Lock()
	health.preventionActive = enabled
	health.mu.Unlock()
}

func (a *Agent) setRuntimePreventionEnabled(enabled bool) {
	a.runtimeHealth.setPreventionEnabled(enabled)
	a.raspBridgeMu.RLock()
	bridge := a.raspBridge
	a.raspBridgeMu.RUnlock()
	if bridge != nil {
		bridge.health.setPreventionEnabled(enabled)
	}
}

func (health *runtimeControlHealth) Degrade(reason string, integrityFailure bool) runtimeControlHealthSnapshot {
	health.mu.Lock()
	health.status = controlHealthDegraded
	health.reason = reason
	health.watchdogAt = health.now().UTC()
	if integrityFailure {
		health.preventionActive = false
	}
	health.mu.Unlock()
	return health.Snapshot()
}

func (health *runtimeControlHealth) TouchWatchdog() {
	health.mu.Lock()
	health.watchdogAt = health.now().UTC()
	if health.publication.Status == controlHealthHealthy && health.reason != "binary_integrity_failed" && health.reason != "signed_config_integrity_failed" && health.reason != "authorization_failed" && health.reason != "restart_budget_exhausted" {
		health.status = controlHealthHealthy
		health.reason = ""
	}
	health.mu.Unlock()
}

func (health *runtimeControlHealth) recordPublicationFailure(err error) {
	health.mu.Lock()
	health.publication.Status = controlHealthDegraded
	health.publication.RetryCount++
	health.publication.LastError = err.Error()
	if health.status == controlHealthHealthy || health.reason == "control_health_delivery_unavailable" {
		health.status = controlHealthDegraded
		health.reason = "control_health_delivery_unavailable"
	}
	health.mu.Unlock()
}

func (health *runtimeControlHealth) recordPublicationSuccess() {
	health.mu.Lock()
	wasDegraded := health.publication.Status == controlHealthDegraded
	health.publication.Status = controlHealthHealthy
	health.publication.LastError = ""
	if wasDegraded && health.reason == "control_health_delivery_unavailable" {
		health.status = controlHealthHealthy
		health.reason = ""
	}
	health.mu.Unlock()
}

func (health *runtimeControlHealth) CheckWatchdog(maxAge time.Duration) runtimeControlHealthSnapshot {
	health.mu.Lock()
	if health.now().Sub(health.watchdogAt) > maxAge {
		health.status = controlHealthDegraded
		health.reason = "watchdog_stale"
	}
	health.mu.Unlock()
	return health.Snapshot()
}

func (health *runtimeControlHealth) RecordWatchdogRestart() bool {
	health.mu.Lock()
	defer health.mu.Unlock()
	if health.restartCount >= health.limits.RestartBudget {
		health.status = controlHealthDegraded
		health.reason = "restart_budget_exhausted"
		health.preventionActive = false
		health.watchdogAt = health.now().UTC()
		return false
	}
	health.restartCount++
	health.watchdogAt = health.now().UTC()
	return true
}

type runtimeBudget struct {
	limits RuntimeLimits
	now    func() time.Time
	start  time.Time
	read   int
}

func newRuntimeBudget(limits RuntimeLimits, now func() time.Time) *runtimeBudget {
	return &runtimeBudget{limits: limits, now: now, start: now()}
}

func (budget *runtimeBudget) Allow(ctx context.Context, bytes int) bool {
	if ctx.Err() != nil {
		return false
	}
	budget.read += bytes
	if budget.limits.ReadBytes > 0 && budget.read > budget.limits.ReadBytes {
		return false
	}
	return budget.limits.CPUBudget <= 0 || budget.now().Sub(budget.start) <= budget.limits.CPUBudget
}

type restartBudget struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	now      func() time.Time
	windowAt time.Time
	count    int
}

func newRestartBudget(limit int, window time.Duration, now func() time.Time) *restartBudget {
	return &restartBudget{limit: limit, window: window, now: now}
}

func (budget *restartBudget) Allow() bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	now := budget.now()
	if budget.windowAt.IsZero() || now.Sub(budget.windowAt) >= budget.window {
		budget.windowAt = now
		budget.count = 0
	}
	if budget.count >= budget.limit {
		return false
	}
	budget.count++
	return true
}

func (budget *restartBudget) Count() int {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.count
}
