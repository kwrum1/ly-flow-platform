package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lyflow/ly-flow-platform/server/models"
)

// Consumer reads alerts from Redis streams and stores them in PostgreSQL
type Consumer struct {
	client  *redis.Client
	streams []string
	group   string
	db      *models.DB
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewConsumer creates a new Redis stream consumer
func NewConsumer(redisAddr string, streams []string, group string, db *models.DB) (*Consumer, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "",
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	// Create consumer group for each stream
	for _, stream := range streams {
		err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err()
		if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
			log.Printf("Warning: XGroupCreate failed for %s: %v", stream, err)
		}
	}

	return &Consumer{
		client:  client,
		streams: streams,
		group:   group,
		db:      db,
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

	for {
		select {
		case <-c.stopCh:
			log.Printf("Worker %s stopping", workerID)
			return
		case <-ctx.Done():
			log.Printf("Worker %s context cancelled", workerID)
			return
		default:
			c.processStreams(ctx, workerID)
			<-ticker.C
		}
	}
}

// processStreams reads from all streams using XREADGROUP
func (c *Consumer) processStreams(ctx context.Context, workerID string) {
	// Build stream keys for XREADGROUP
	streamKeys := make([]redis.XReadGroupArgs, 0, len(c.streams))
	for _, stream := range c.streams {
		streamKeys = append(streamKeys, redis.XReadGroupArgs{
			Group:    c.group,
			Consumer: workerID,
			Streams:  []string{stream, ">"},
			Count:    100,
			Block:    time.Second,
		})
	}

	streams := make([]string, len(c.streams))
	for i, s := range c.streams {
		streams[i] = s
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
		c.processMessages(ctx, streamResult.Stream, streamResult.Messages, workerID)
	}
}

// processMessages handles a batch of messages from a single stream
func (c *Consumer) processMessages(ctx context.Context, stream string, messages []redis.XMessage, workerID string) {
	if len(messages) == 0 {
		return
	}

	log.Printf("Worker %s: processing %d messages from %s", workerID, len(messages), stream)

	events := make([]*models.Event, 0, len(messages))
	messageIDs := make([]string, 0, len(messages))

	for _, msg := range messages {
		alert := &models.AlertInput{}
		if err := json.Unmarshal([]byte(msg.Values["data"].(string)), alert); err != nil {
			log.Printf("Failed to unmarshal alert: %v", err)
			continue
		}

		event := alert.ToEvent()
		events = append(events, event)
		messageIDs = append(messageIDs, msg.ID)
	}

	// Batch insert events
	if len(events) > 0 {
		if err := c.db.BatchInsertEvents(ctx, events); err != nil {
			log.Printf("Failed to insert events: %v", err)
			return
		}
		log.Printf("Worker %s: inserted %d events from %s", workerID, len(events), stream)
	}

	// Acknowledge processed messages
	for _, id := range messageIDs {
		if err := c.client.XAck(ctx, stream, c.group, id).Err(); err != nil {
			log.Printf("XACK failed for %s: %v", id, err)
		}
	}
}