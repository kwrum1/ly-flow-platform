package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
)

type Engine struct {
	cfg      config.Config
	client   *redis.Client
	stats    Stats
	state    atomic.Pointer[engineState]
	reliable *transport.RedisConsumer
	health   *runtimeHealth
}

type engineState struct {
	bundle   *Bundle
	manifest LifecycleManifest
}

type Stats struct {
	Received    atomic.Uint64
	Alerts      atomic.Uint64
	DeadLetters atomic.Uint64
	Reloads     atomic.Uint64
}

func New(cfg config.Config, client *redis.Client) *Engine {
	if cfg.ReadCount <= 0 {
		cfg.ReadCount = 64
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 1 << 20
	}
	if cfg.CPUBudget <= 0 {
		cfg.CPUBudget = 100 * time.Millisecond
	}
	if cfg.MemoryBudgetBytes <= 0 {
		cfg.MemoryBudgetBytes = 16 << 20
	}
	if cfg.RestartBudget <= 0 {
		cfg.RestartBudget = 3
	}
	e := &Engine{cfg: cfg, client: client, health: newRuntimeHealth(cfg)}
	spool, err := transport.RuntimeSpoolFromEnv("security-engine-consumer")
	if err != nil {
		log.Printf("[security-engine] encrypted transport spool disabled: %v", err)
	}
	e.reliable = transport.NewRedisConsumer(transport.ConsumerConfig{
		Client: client, Group: cfg.ConsumerGroup, Consumer: cfg.ConsumerName, Spool: spool,
		Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
	})
	e.state.Store(&engineState{bundle: EmptyBundle()})
	return e
}

func (e *Engine) EnsureGroups(ctx context.Context) error {
	for _, stream := range e.cfg.InputStreams {
		if err := e.client.XGroupCreateMkStream(ctx, stream, e.cfg.ConsumerGroup, "0").Err(); err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
			return fmt.Errorf("create consumer group for %s: %w", stream, err)
		}
	}
	return nil
}

func (e *Engine) Run(ctx context.Context) error {
	if _, err := e.VerifyIntegrity(ctx); err != nil {
		return fmt.Errorf("verify runtime integrity: %w", err)
	}
	if err := e.EnsureGroups(ctx); err != nil {
		e.health.degrade("transport_unavailable", false)
		return err
	}
	if err := transport.RegisterProducer(ctx, e.client, "security-engine"); err != nil {
		e.health.degrade("transport_unavailable", false)
		return fmt.Errorf("register reliable producer: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err := e.consumeOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (e *Engine) consumeOnce(ctx context.Context) error {
	e.health.touchWatchdog()
	if err := transport.RegisterProducer(ctx, e.client, "security-engine"); err != nil {
		e.health.degrade("transport_unavailable", false)
		return fmt.Errorf("renew reliable producer lease: %w", err)
	}
	started := time.Now()
	for _, stream := range e.cfg.InputStreams {
		if err := e.reliable.Reclaim(ctx, stream, e.process); err != nil {
			e.health.degrade("transport_unavailable", false)
			return fmt.Errorf("reclaim pending stream %s: %w", stream, err)
		}
		if time.Since(started) > e.cfg.CPUBudget {
			e.health.degrade("cpu_budget_exceeded", false)
			return ErrRuntimeCPUBudget
		}
	}
	streams := make([]string, 0, len(e.cfg.InputStreams)*2)
	streams = append(streams, e.cfg.InputStreams...)
	for range e.cfg.InputStreams {
		streams = append(streams, ">")
	}
	results, err := e.client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: e.cfg.ConsumerGroup, Consumer: e.cfg.ConsumerName, Streams: streams, Count: e.cfg.ReadCount, Block: e.cfg.ReadBlock}).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			e.health.degrade("transport_unavailable", false)
			if strings.Contains(err.Error(), "NOGROUP") {
				if groupErr := e.EnsureGroups(ctx); groupErr != nil {
					return errors.Join(fmt.Errorf("read input streams: %w", err), groupErr)
				}
			}
			return fmt.Errorf("read input streams: %w", err)
		}
		e.health.touchWatchdog()
		return nil
	}
	e.health.touchWatchdog()
	for _, result := range results {
		if err := e.reliable.Handle(ctx, result.Stream, result.Messages, e.process); err != nil {
			return fmt.Errorf("durable handoff for %s: %w", result.Stream, err)
		}
	}
	return nil
}

func (e *Engine) process(ctx context.Context, delivery transport.Delivery) (transport.DurableOutcome, error) {
	e.health.touchWatchdog()
	e.stats.Received.Add(1)
	encoded, err := json.Marshal(delivery.Values)
	if err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("measure security-engine delivery: %w", err)
	}
	if len(encoded) > e.cfg.MaxMessageBytes || len(encoded) > e.cfg.MemoryBudgetBytes {
		e.health.degrade("memory_budget_exceeded", false)
		return transport.DurableOutcome{}, ErrRuntimeMemoryBudget
	}
	uid := transport.DeterministicUID("security_engine_receipts", delivery.Stream, delivery.MessageID)
	processed, err := e.client.HExists(ctx, "transport_reliability:security_engine", uid).Result()
	if err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("load security-engine receipt: %w", err)
	}
	if processed {
		return transport.DurableOutcome{UID: uid, Sink: "security_engine_receipts"}, nil
	}
	env, err := decodeTelemetry(delivery.Values)
	if err != nil {
		e.stats.DeadLetters.Add(1)
		return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, err)
	}
	if err := env.Validate(); err != nil {
		e.stats.DeadLetters.Add(1)
		return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, err)
	}
	alerts := e.state.Load().bundle.Match(env)
	for _, alert := range alerts {
		alert.ID = alertID(env.ID, alert.RuleID)
		alert.OccurredAt = env.ObservedAt
		alert.Source = "ly-security-engine"
		alert.Entities = env.Entities
		if env.RawReference != nil {
			alert.EvidenceRefs = []contracts.RawReference{*env.RawReference}
		}
		alert.CandidateOnly = alert.CandidateOnly || alert.Category == contracts.TelemetryRASP
		if err := e.emitAlert(ctx, alert); err != nil {
			return transport.DurableOutcome{}, fmt.Errorf("emit alert %s: %w", alert.ID, err)
		}
		e.stats.Alerts.Add(1)
	}
	if err := e.client.HSet(ctx, "transport_reliability:security_engine", uid, delivery.MessageID).Err(); err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("persist security-engine receipt: %w", err)
	}
	return transport.DurableOutcome{UID: uid, Sink: "security_engine_receipts"}, nil
}

func (e *Engine) Activate(bundle *Bundle, manifest LifecycleManifest) {
	e.state.Store(&engineState{bundle: bundle, manifest: manifest})
	e.stats.Reloads.Add(1)
	e.health.recover()
}

func (e *Engine) emitAlert(ctx context.Context, alert contracts.ComponentAlert) error {
	if err := alert.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	stream := e.outputStream(alert.Category)
	return e.client.Eval(ctx, securityAlertScript, []string{"transport_reliability:security_alerts", stream}, alert.ID, string(data)).Err()
}

func (e *Engine) outputStream(category contracts.TelemetryCategory) string {
	switch category {
	case contracts.TelemetryTraffic:
		return e.cfg.DPIStream
	case contracts.TelemetryRuntime:
		return e.cfg.RuntimeStream
	case contracts.TelemetryRASP:
		return e.cfg.RASPStream
	case contracts.TelemetryLogAudit:
		return e.cfg.LogAuditStream
	default:
		return "alerts:security"
	}
}

const securityAlertScript = `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return redis.call('HGET', KEYS[1], ARGV[1]) end
local id = redis.call('XADD', KEYS[2], '*', 'event_uid', ARGV[1], 'data', ARGV[2])
redis.call('HSET', KEYS[1], ARGV[1], id)
return id
`

func decodeTelemetry(values map[string]any) (contracts.TelemetryEnvelope, error) {
	data, ok := values["data"]
	if !ok {
		encoded, err := json.Marshal(values)
		if err != nil {
			return contracts.TelemetryEnvelope{}, err
		}
		data = string(encoded)
	}
	var raw []byte
	switch v := data.(type) {
	case string:
		raw = []byte(v)
	case []byte:
		raw = v
	default:
		return contracts.TelemetryEnvelope{}, fmt.Errorf("unsupported data type %T", data)
	}
	var env contracts.TelemetryEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return contracts.TelemetryEnvelope{}, err
	}
	return env, nil
}

func alertID(eventID, ruleID string) string {
	sum := sha256.Sum256([]byte(eventID + ":" + ruleID))
	return "alert-" + hex.EncodeToString(sum[:8])
}
