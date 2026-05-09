package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"ly-flow-platform/probe/pkg/model"

	"github.com/go-redis/redis/v8"
)

// Producer sends FlowData to Redis Stream
type Producer struct {
	client       *redis.Client
	stream       string
	batchSize    int64
	flushInterval time.Duration
	batch        []*model.FlowData
	mu           sync.Mutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewProducer creates a new Redis producer
func NewProducer(addr, password string, db int, stream string, batchSize int64, flushInterval time.Duration) (*Producer, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
		PoolSize: 10,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Producer{
		client:        client,
		stream:        stream,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		batch:         make([]*model.FlowData, 0, batchSize),
		stopCh:        make(chan struct{}),
	}, nil
}

// Start begins the background flush goroutine
func (p *Producer) Start() {
	p.wg.Add(1)
	go p.flushLoop()
}

// Stop gracefully stops the producer and flushes remaining data
func (p *Producer) Stop() error {
	close(p.stopCh)
	p.wg.Wait()

	// Final flush
	p.mu.Lock()
	if len(p.batch) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.flushBatch(ctx); err != nil {
			log.Printf("Error flushing final batch: %v", err)
		}
	}
	p.mu.Unlock()

	return p.client.Close()
}

// Send adds a FlowData to the batch and triggers flush if needed
func (p *Producer) Send(data *model.FlowData) error {
	p.mu.Lock()
	p.batch = append(p.batch, data)
	shouldFlush := int64(len(p.batch)) >= p.batchSize
	p.mu.Unlock()

	if shouldFlush {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.flushBatch(ctx)
	}

	return nil
}

// SendBatch adds multiple FlowData to the batch
func (p *Producer) SendBatch(data []*model.FlowData) error {
	p.mu.Lock()
	p.batch = append(p.batch, data...)
	shouldFlush := int64(len(p.batch)) >= p.batchSize
	p.mu.Unlock()

	if shouldFlush {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.flushBatch(ctx)
	}

	return nil
}

// flushLoop periodically flushes the batch
func (p *Producer) flushLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.mu.Lock()
			if len(p.batch) > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := p.flushBatch(ctx); err != nil {
					log.Printf("Error flushing batch: %v", err)
				}
				cancel()
			}
			p.mu.Unlock()
		}
	}
}

// flushBatch sends the current batch to Redis
func (p *Producer) flushBatch(ctx context.Context) error {
	if len(p.batch) == 0 {
		return nil
	}

	// Build pipeline for batch insert
	pipe := p.client.Pipeline()
	for _, data := range p.batch {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling flow data: %v", err)
			continue
		}

		pipe.XAdd(ctx, &redis.XAddArgs{
			Stream: p.stream,
			MaxLen: 10000, // Trim old entries
			Approx: true,
			Values: map[string]interface{}{
				"data": string(jsonData),
			},
		})
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute pipeline: %w", err)
	}

	log.Printf("Flushed %d flow records to %s", len(p.batch), p.stream)

	// Clear batch
	p.batch = p.batch[:0]

	return nil
}

// Len returns the current batch size
func (p *Producer) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.batch)
}
