package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
)

type Engine struct {
	cfg    config.Config
	client *redis.Client
	stats  Stats
	rules  atomic.Pointer[Bundle]
	mu     sync.Mutex
}

type Stats struct {
	Received    atomic.Uint64
	Alerts      atomic.Uint64
	DeadLetters atomic.Uint64
	Reloads     atomic.Uint64
}

type Snapshot struct {
	Service       string            `json:"service"`
	Status        string            `json:"status"`
	Inputs        []string          `json:"inputs"`
	Outputs       map[string]string `json:"outputs"`
	BundleVersion string            `json:"bundle_version"`
	RuleCounts    map[string]int    `json:"rule_counts"`
	Received      uint64            `json:"received"`
	Alerts        uint64            `json:"alerts"`
	DeadLetters   uint64            `json:"dead_letters"`
	Reloads       uint64            `json:"reloads"`
}

func New(cfg config.Config, client *redis.Client) *Engine {
	e := &Engine{cfg: cfg, client: client}
	e.rules.Store(EmptyBundle())
	return e
}

func (e *Engine) EnsureGroups(ctx context.Context) {
	for _, stream := range e.cfg.InputStreams {
		if err := e.client.XGroupCreateMkStream(ctx, stream, e.cfg.ConsumerGroup, "0").Err(); err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
			log.Printf("[security-engine] create group failed stream=%s err=%v", stream, err)
		}
	}
}

func (e *Engine) Run(ctx context.Context) {
	e.EnsureGroups(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			e.consumeOnce(ctx)
		}
	}
}

func (e *Engine) consumeOnce(ctx context.Context) {
	streams := make([]string, 0, len(e.cfg.InputStreams)*2)
	streams = append(streams, e.cfg.InputStreams...)
	for range e.cfg.InputStreams {
		streams = append(streams, ">")
	}
	results, err := e.client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: e.cfg.ConsumerGroup, Consumer: e.cfg.ConsumerName, Streams: streams, Count: 64, Block: e.cfg.ReadBlock}).Result()
	if err != nil {
		if err != redis.Nil {
			log.Printf("[security-engine] read failed: %v", err)
			if strings.Contains(err.Error(), "NOGROUP") {
				e.EnsureGroups(ctx)
			}
		}
		return
	}
	for _, result := range results {
		ids := make([]string, 0, len(result.Messages))
		for _, msg := range result.Messages {
			ids = append(ids, msg.ID)
			e.process(ctx, result.Stream, msg)
		}
		if len(ids) > 0 {
			_ = e.client.XAck(ctx, result.Stream, e.cfg.ConsumerGroup, ids...).Err()
		}
	}
}

func (e *Engine) process(ctx context.Context, stream string, msg redis.XMessage) {
	e.stats.Received.Add(1)
	env, err := decodeTelemetry(msg.Values)
	if err != nil {
		e.deadLetter(ctx, stream, msg.ID, msg.Values, err)
		return
	}
	if err := env.Validate(); err != nil {
		e.deadLetter(ctx, stream, msg.ID, msg.Values, err)
		return
	}
	alerts := e.rules.Load().Match(env)
	for _, alert := range alerts {
		alert.ID = alertID(env.ID, alert.RuleID)
		alert.OccurredAt = env.ObservedAt
		alert.Source = "ly-security-engine"
		alert.Entities = env.Entities
		if env.RawReference != nil {
			alert.EvidenceRefs = []contracts.RawReference{*env.RawReference}
		}
		alert.CandidateOnly = alert.CandidateOnly || alert.Category == contracts.TelemetryRASP && !e.cfg.BlockByDefault
		if err := e.emitAlert(ctx, alert); err != nil {
			log.Printf("[security-engine] emit alert failed: %v", err)
			continue
		}
		e.stats.Alerts.Add(1)
	}
}

func (e *Engine) Reload(bundle *Bundle) {
	if bundle == nil {
		bundle = EmptyBundle()
	}
	e.rules.Store(bundle)
	e.stats.Reloads.Add(1)
}

func (e *Engine) Snapshot() Snapshot {
	bundle := e.rules.Load()
	return Snapshot{Service: "ly-security-engine", Status: "running", Inputs: e.cfg.InputStreams, Outputs: map[string]string{"dpi": e.cfg.DPIStream, "runtime": e.cfg.RuntimeStream, "rasp": e.cfg.RASPStream, "log_audit": e.cfg.LogAuditStream}, BundleVersion: bundle.Version, RuleCounts: bundle.Counts(), Received: e.stats.Received.Load(), Alerts: e.stats.Alerts.Load(), DeadLetters: e.stats.DeadLetters.Load(), Reloads: e.stats.Reloads.Load()}
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
	return e.client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]any{"data": string(data)}}).Err()
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

func (e *Engine) deadLetter(ctx context.Context, stream, msgID string, values map[string]any, cause error) {
	e.stats.DeadLetters.Add(1)
	raw, _ := json.Marshal(values)
	_ = e.client.XAdd(ctx, &redis.XAddArgs{Stream: "deadletter:" + stream, Values: map[string]any{"source_stream": stream, "source_message_id": msgID, "reason": cause.Error(), "raw": string(raw), "created_at": time.Now().UTC().Format(time.RFC3339Nano)}}).Err()
}

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
