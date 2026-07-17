package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lyflow/ly-flow-platform/server/internal/redisconfig"
	"github.com/lyflow/ly-flow-platform/server/unified"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

type UnifiedConsumer struct {
	client     *redis.Client
	redisAddr  string
	streams    []string
	group      string
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	eventStats *unified.EventStats
	statsMu    sync.RWMutex
	spool      *transport.EncryptedSpool
	reliable   *transport.RedisConsumer
	producer   *transport.RedisProducer
}

func NewUnifiedConsumer(redisAddr string, streams []string, group string) (*UnifiedConsumer, error) {
	uc := &UnifiedConsumer{
		redisAddr:  redisAddr,
		streams:    streams,
		group:      group,
		eventStats: &unified.EventStats{},
	}
	uc.ctx, uc.cancel = context.WithCancel(context.Background())

	if err := uc.initRedis(); err != nil {
		log.Printf("[Consumer] Redis 连接失败: %v", err)
		return nil, err
	}
	spool, err := transport.RuntimeSpoolFromEnv("server-unified-consumer")
	if err != nil {
		return nil, fmt.Errorf("configure encrypted transport spool: %w", err)
	}
	uc.spool = spool
	uc.reliable = transport.NewRedisConsumer(transport.ConsumerConfig{
		Client: uc.client, Group: uc.group, Consumer: "unified-consumer", Spool: spool,
		Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
	})
	if spool != nil {
		uc.producer, err = transport.NewRedisProducer(transport.ProducerConfig{
			Client: uc.client, Name: "server-unified", Spool: spool,
			Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
		})
		if err != nil {
			return nil, fmt.Errorf("configure reliable unified producer: %w", err)
		}
	}

	return uc, nil
}

func (c *UnifiedConsumer) initRedis() error {
	c.client = redis.NewClient(redisconfig.Options(c.redisAddr, 0))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis 连接失败: %w", err)
	}

	for _, stream := range c.streams {
		err := c.client.XGroupCreateMkStream(ctx, stream, c.group, "0").Err()
		if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
			log.Printf("[Consumer] 创建消费者组失败 %s: %v", stream, err)
		}
	}
	if err := transport.RegisterProducer(ctx, c.client, "server-unified"); err != nil {
		return err
	}

	log.Printf("[Consumer] Redis 连接成功, 消费流: %v", c.streams)
	return nil
}

func (c *UnifiedConsumer) Start() {
	log.Printf("[Consumer] 启动统一事件消费者...")

	c.wg.Add(1)
	go c.consumeLoop()

	log.Printf("[Consumer] 统一事件消费者已启动")
}

func (c *UnifiedConsumer) Stop() {
	log.Printf("[Consumer] 停止统一事件消费者...")
	c.cancel()
	c.wg.Wait()
	if c.client != nil {
		c.client.Close()
	}
	log.Printf("[Consumer] 统一事件消费者已停止")
}

func (c *UnifiedConsumer) consumeLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.consumeAllStreams()
		}
	}
}

func (c *UnifiedConsumer) consumeAllStreams() {
	ctx := c.ctx
	if err := transport.RegisterProducer(ctx, c.client, "server-unified"); err != nil {
		log.Printf("[Consumer] reliable producer lease renewal failed: %v", err)
		return
	}

	for _, stream := range c.streams {
		if err := c.reliable.Reclaim(ctx, stream, c.processDelivery); err != nil {
			log.Printf("[Consumer] pending reclaim failed stream=%s err=%v", stream, err)
			continue
		}
		streams, err := c.client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    c.group,
			Consumer: "unified-consumer",
			Streams:  []string{stream, ">"},
			Count:    100,
			Block:    time.Second,
		}).Result()

		if err != nil || len(streams) == 0 {
			continue
		}

		for _, s := range streams {
			if err := c.reliable.Handle(ctx, s.Stream, s.Messages, c.processDelivery); err != nil {
				log.Printf("[Consumer] durable handoff failed stream=%s err=%v", s.Stream, err)
			}
		}
	}
}

func (c *UnifiedConsumer) processDelivery(ctx context.Context, delivery transport.Delivery) (transport.DurableOutcome, error) {
	data, ok := delivery.Values["data"]
	if !ok {
		return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, fmt.Errorf("data field is required"))
	}

	dataStr, ok := data.(string)
	if !ok {
		return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, fmt.Errorf("data field is not a string"))
	}

	var event unified.UnifiedEvent
	if err := json.Unmarshal([]byte(dataStr), &event); err != nil {
		return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, err)
	}

	if event.ID == "" {
		event.ID = transport.DeterministicUID("unified_event_stats", delivery.Stream, delivery.MessageID)
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	if event.SchemaVersion == "" {
		event.SchemaVersion = "wave3.v1"
	}
	if event.SourceModule == "" {
		event.SourceModule = event.Module
	}
	if event.EntityIDs == nil && (event.AgentID != "" || event.User != "") {
		event.EntityIDs = &unified.EntityIDs{
			AgentID: event.AgentID,
			UserID:  event.User,
		}
	}
	if event.RawReference == nil {
		event.RawReference = &unified.RawReference{MessageID: delivery.MessageID}
	}

	newDelivery, err := c.client.HSetNX(ctx, "transport_reliability:unified_event_stats", event.ID, delivery.MessageID).Result()
	if err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("persist unified event receipt: %w", err)
	}
	if newDelivery {
		c.updateStats(&event)
	}

	log.Printf("[Consumer] 处理事件: [%s] %s - %s", event.Module, event.EventType, event.Message)
	return transport.DurableOutcome{UID: event.ID, Sink: "unified_event_stats"}, nil
}

func (c *UnifiedConsumer) updateStats(event *unified.UnifiedEvent) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()

	c.eventStats.TotalEvents++
	c.eventStats.ByModule[event.Module]++
	c.eventStats.BySeverity[event.Severity]++
	c.eventStats.BySource[event.Source]++

	if event.SrcIP != "" {
		c.eventStats.BySrcIP[event.SrcIP]++
	}

	if event.Alert {
		c.eventStats.TotalAlerts++
	}

	if event.Severity == unified.SeverityCritical {
		c.eventStats.CriticalCount++
	} else if event.Severity == unified.SeverityHigh {
		c.eventStats.HighCount++
	} else if event.Severity == unified.SeverityMedium {
		c.eventStats.MediumCount++
	} else {
		c.eventStats.LowCount++
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if event.Timestamp.After(today) {
		c.eventStats.TodayEvents++
		if event.Alert {
			c.eventStats.TodayAlerts++
		}
	}
}

func (c *UnifiedConsumer) GetStats() *unified.EventStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	stats := &unified.EventStats{
		TotalEvents:   c.eventStats.TotalEvents,
		TodayEvents:   c.eventStats.TodayEvents,
		TotalAlerts:   c.eventStats.TotalAlerts,
		TodayAlerts:   c.eventStats.TodayAlerts,
		CriticalCount: c.eventStats.CriticalCount,
		HighCount:     c.eventStats.HighCount,
		MediumCount:   c.eventStats.MediumCount,
		LowCount:      c.eventStats.LowCount,
		ByModule:      make(map[unified.ModuleType]int64),
		BySeverity:    make(map[unified.Severity]int64),
		BySource:      make(map[string]int64),
		BySrcIP:       make(map[string]int64),
	}

	for k, v := range c.eventStats.ByModule {
		stats.ByModule[k] = v
	}
	for k, v := range c.eventStats.BySeverity {
		stats.BySeverity[k] = v
	}
	for k, v := range c.eventStats.BySource {
		stats.BySource[k] = v
	}
	for k, v := range c.eventStats.BySrcIP {
		stats.BySrcIP[k] = v
	}

	return stats
}

func (c *UnifiedConsumer) PublishEvent(event *unified.UnifiedEvent) error {
	if event.ID == "" {
		event.ID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if c.producer == nil {
		return fmt.Errorf("encrypted durable unified producer is unavailable")
	}
	return c.producer.Publish(context.Background(), "events:unified", event.ID, map[string]interface{}{
		"module":     string(event.Module),
		"event_type": event.EventType,
		"severity":   string(event.Severity),
		"data":       string(data),
		"timestamp":  event.Timestamp.Format(time.RFC3339),
	})
}
