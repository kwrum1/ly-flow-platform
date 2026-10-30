package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type raspBridgePublisher interface {
	Publish(ctx context.Context, event contracts.TelemetryEnvelope) error
}

type raspBridgeRuntimeConfig struct {
	CurrentToken  string
	FallbackPath  string
	QueueCapacity int
	TokenOverlap  time.Duration
	Now           func() time.Time
	Publisher     raspBridgePublisher
	StartWorker   bool
	Limits        RuntimeLimits
}

type raspBridgeHealth = runtimeControlHealthSnapshot

type raspBridgeRuntime struct {
	agent            *Agent
	tokens           *raspBridgeTokenSet
	fallback         *raspFallbackLog
	publisher        raspBridgePublisher
	queue            chan raspBridgeDeliveryItem
	now              func() time.Time
	ctx              context.Context
	cancel           context.CancelFunc
	closeOnce        sync.Once
	worker           sync.WaitGroup
	deliveryFinished chan struct{}
	accepted         atomic.Uint64
	delivered        atomic.Uint64
	rejected         atomic.Uint64
	deliveryFailures atomic.Uint64
	fallbackCount    atomic.Uint64
	healthMu         sync.RWMutex
	lastDeliveredAt  time.Time
	lastError        string
	limits           RuntimeLimits
	health           *runtimeControlHealth
}

func newRASPBridgeRuntime(agent *Agent, config raspBridgeRuntimeConfig) (*raspBridgeRuntime, error) {
	if agent == nil || config.Publisher == nil || config.QueueCapacity <= 0 || strings.TrimSpace(config.FallbackPath) == "" {
		return nil, errors.New("RASP bridge runtime configuration invalid")
	}
	limits := config.Limits
	if limits.QueueCapacity <= 0 {
		limits = agentRuntimeLimits()
	}
	queueCapacity := min(config.QueueCapacity, limits.QueueCapacity)
	tokens, err := newRASPBridgeTokenSet(config.CurrentToken, config.TokenOverlap, config.Now)
	if err != nil {
		return nil, err
	}
	fallback, err := newRASPBridgeFallbackLog(config.FallbackPath, config.Now)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(agent.ctx)
	runtime := &raspBridgeRuntime{
		agent: agent, tokens: tokens, fallback: fallback, publisher: config.Publisher,
		queue: make(chan raspBridgeDeliveryItem, queueCapacity), now: config.Now, limits: limits,
		ctx: ctx, cancel: cancel, deliveryFinished: make(chan struct{}, queueCapacity+1),
		health: newRuntimeControlHealth("agent-rasp-bridge", limits, config.Now),
	}
	runtime.health.setPreventionEnabled(agent.raspPolicyEnabled())
	if config.StartWorker {
		runtime.worker.Add(1)
		go runtime.runDelivery()
	}
	return runtime, nil
}

func (bridge *raspBridgeRuntime) Close() {
	bridge.closeOnce.Do(func() {
		bridge.cancel()
		bridge.worker.Wait()
	})
}

func (bridge *raspBridgeRuntime) RotateToken(next string) error {
	return bridge.tokens.Rotate(next)
}

func (bridge *raspBridgeRuntime) enqueue(item raspBridgeDeliveryItem) (bool, error) {
	select {
	case bridge.queue <- item:
		bridge.accepted.Add(1)
		return true, nil
	default:
		bridge.rejected.Add(1)
		bridge.health.Degrade("queue_budget_exceeded", false)
		healthErr := bridge.agent.publishControlHealth(bridge.agent.runtimeHealth.Degrade("queue_budget_exceeded", false))
		fallbackErr := bridge.persistFallback(item, raspFallbackQueueFull)
		if fallbackErr != nil {
			bridge.setLastError(fallbackErr)
		}
		return false, errors.Join(healthErr, fallbackErr)
	}
}

func (bridge *raspBridgeRuntime) runDelivery() {
	defer bridge.worker.Done()
	for {
		select {
		case <-bridge.ctx.Done():
			return
		case item := <-bridge.queue:
			bridge.deliver(item)
		}
	}
}

func (bridge *raspBridgeRuntime) deliver(item raspBridgeDeliveryItem) {
	deliveryContext := bridge.ctx
	cancel := func() {}
	if bridge.limits.CPUBudget > 0 {
		deliveryContext, cancel = context.WithTimeout(bridge.ctx, bridge.limits.CPUBudget)
	}
	defer cancel()
	if err := bridge.publisher.Publish(deliveryContext, item.telemetry); err != nil {
		bridge.deliveryFailures.Add(1)
		bridge.health.Degrade("delivery_degraded", false)
		bridge.setLastError(err)
		if fallbackErr := bridge.persistFallback(item, raspFallbackDeliveryFailed); fallbackErr != nil {
			bridge.setLastError(errors.Join(err, fallbackErr))
		}
	} else {
		bridge.delivered.Add(1)
		bridge.health.TouchWatchdog()
		bridge.healthMu.Lock()
		bridge.lastDeliveredAt = bridge.now().UTC()
		bridge.lastError = ""
		bridge.healthMu.Unlock()
	}
	select {
	case bridge.deliveryFinished <- struct{}{}:
	default:
	}
}

func (bridge *raspBridgeRuntime) persistFallback(item raspBridgeDeliveryItem, reason raspFallbackReason) error {
	if err := bridge.fallback.Append(item.request, reason); err != nil {
		return fmt.Errorf("persist RASP fallback: %w", err)
	}
	bridge.fallbackCount.Add(1)
	return nil
}

func (bridge *raspBridgeRuntime) setLastError(err error) {
	bridge.healthMu.Lock()
	bridge.lastError = err.Error()
	bridge.healthMu.Unlock()
}

func (bridge *raspBridgeRuntime) Health() raspBridgeHealth {
	return bridge.health.Snapshot()
}

type agentRASPBridgePublisher struct{ agent *Agent }

func (publisher agentRASPBridgePublisher) Publish(ctx context.Context, event contracts.TelemetryEnvelope) error {
	if err := publisher.agent.publishAgentStream(ctx, publisher.agent.cfg.RASPTelemetryStream, structToMap(event), "telemetry_rasp"); err != nil {
		return err
	}
	if strings.HasPrefix(event.EventType, "rasp.protection") {
		return nil
	}
	// Also emit a normalized component alert so XDR/incident correlation sees
	// RASP detections, not only the telemetry stream.
	alert, err := componentAlertFromRASP(raspEventInput{
		RuleID:      firstNonEmpty(jsonString(event.Fields, "rule_id"), event.EventType),
		RuleName:    firstNonEmpty(jsonString(event.Fields, "rule_name"), event.EventType),
		HookType:    firstNonEmpty(jsonString(event.Fields, "phase"), "request"),
		Language:    jsonString(event.Fields, "language"),
		Runtime:     jsonString(event.Fields, "runtime"),
		Application: firstNonEmpty(jsonString(event.Fields, "application"), jsonString(event.Fields, "app")),
		Action:      jsonString(event.Fields, "action"),
		Evidence:    firstNonEmpty(jsonString(event.Fields, "evidence"), event.Excerpt),
		OccurredAt:  event.ObservedAt,
	}, publisher.agent, contracts.RawReference{Path: "rasp-bridge"})
	if err != nil {
		return nil
	}
	return publisher.agent.publishComponentAlert(alert)
}
