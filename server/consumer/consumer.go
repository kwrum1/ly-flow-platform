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
	"github.com/lyflow/ly-flow-platform/server/models"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

// Consumer reads alerts from Redis streams and stores them in PostgreSQL
type Consumer struct {
	client  *redis.Client
	streams []string
	group   string
	db      *models.DB
	spool   *transport.EncryptedSpool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewConsumer creates a new Redis stream consumer
func NewConsumer(redisAddr string, streams []string, group string, db *models.DB) (*Consumer, error) {
	client := redis.NewClient(redisconfig.Options(redisAddr, 0))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}
	spool, err := transport.RuntimeSpoolFromEnv("server-consumer")
	if err != nil {
		return nil, fmt.Errorf("configure encrypted transport spool: %w", err)
	}

	// Create consumer group for each stream
	for _, stream := range streams {
		err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err()
		if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
			log.Printf("Warning: XGroupCreate failed for %s: %v", stream, err)
		}
	}
	if err := transport.RegisterProducer(ctx, client, "server-consumer"); err != nil {
		return nil, err
	}

	return &Consumer{
		client:  client,
		streams: streams,
		group:   group,
		db:      db,
		spool:   spool,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start begins consuming from all streams with multiple goroutines
func (c *Consumer) Start(ctx context.Context, numWorkers int) {
	log.Printf("Starting %d consumer workers for streams: %v", numWorkers, c.streams)

	for i := 0; i < numWorkers; i++ {
		c.wg.Add(1)
		workerID := fmt.Sprintf("worker-%d", i)
		go c.runWorker(ctx, workerID)
	}
}

// Stop gracefully stops all consumer workers
func (c *Consumer) Stop() {
	log.Println("Stopping consumer workers...")
	close(c.stopCh)
	c.wg.Wait()
	c.client.Close()
	log.Println("Consumer workers stopped")
}

// runWorker is the main loop for a single consumer worker
func (c *Consumer) runWorker(ctx context.Context, workerID string) {
	defer c.wg.Done()
	log.Printf("Worker %s started", workerID)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	reliable := transport.NewRedisConsumer(transport.ConsumerConfig{
		Client: c.client, Group: c.group, Consumer: workerID, Spool: c.spool,
		Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
	})

	for {
		select {
		case <-c.stopCh:
			log.Printf("Worker %s stopping", workerID)
			return
		case <-ctx.Done():
			log.Printf("Worker %s context cancelled", workerID)
			return
		default:
			c.processStreams(ctx, workerID, reliable)
			<-ticker.C
		}
	}
}

// processStreams reads from all streams using XREADGROUP
func (c *Consumer) processStreams(ctx context.Context, workerID string, reliable *transport.RedisConsumer) {
	if err := transport.RegisterProducer(ctx, c.client, "server-consumer"); err != nil {
		log.Printf("reliable producer lease renewal failed worker=%s err=%v", workerID, err)
		return
	}
	for _, stream := range c.streams {
		if err := reliable.Reclaim(ctx, stream, c.deliveryHandler()); err != nil {
			log.Printf("pending reclaim failed stream=%s worker=%s err=%v", stream, workerID, err)
			return
		}
	}

	streams := make([]string, 0, len(c.streams)*2)
	streams = append(streams, c.streams...)
	for range c.streams {
		streams = append(streams, ">")
	}

	result, err := c.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    c.group,
		Consumer: workerID,
		Streams:  streams,
		Count:    100,
		Block:    time.Second,
	}).Result()

	if err != nil {
		if err != redis.Nil {
			log.Printf("XREADGROUP error: %v", err)
		}
		return
	}

	for _, streamResult := range result {
		if err := reliable.Handle(ctx, streamResult.Stream, streamResult.Messages, c.deliveryHandler()); err != nil {
			log.Printf("durable handoff failed stream=%s worker=%s err=%v", streamResult.Stream, workerID, err)
		}
	}
}

func (c *Consumer) deliveryHandler() transport.Handler {
	return func(ctx context.Context, delivery transport.Delivery) (transport.DurableOutcome, error) {
		alert := &models.AlertInput{}
		data, ok := delivery.Values["data"].(string)
		if !ok {
			return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, fmt.Errorf("data is not a string"))
		}
		if err := json.Unmarshal([]byte(data), alert); err != nil {
			return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, err)
		}
		event := alert.ToEvent()
		event.EventUID = transport.DeterministicUID("events", delivery.Stream, delivery.MessageID)
		if _, err := c.db.InsertEvent(ctx, event); err != nil {
			return transport.DurableOutcome{}, fmt.Errorf("materialize event %s: %w", event.EventUID, err)
		}
		return transport.DurableOutcome{UID: event.EventUID, Sink: "events"}, nil
	}
}
