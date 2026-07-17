package redis

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"
)

type Consumer struct {
	client    *redis.Client
	inStream  string
	outStream string
	group     string
	name      string
	block     time.Duration
	batch     int64
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	running   atomic.Bool
	stats     struct {
		Processed uint64
		Alerts    uint64
		Errors    uint64
	}
	onFlow         func(msg XMessage)
	onFlowReliable func(context.Context, XMessage) error
	spool          *transport.EncryptedSpool
}

type XMessage struct {
	ID     string
	Values map[string]interface{}
}

func NewConsumer(addr, username, password string, db int, in, out, group, name string, workers int, blockSec int) *Consumer {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Consumer{
		client:    redis.NewClient(&redis.Options{Addr: addr, Username: username, Password: password, DB: db}),
		inStream:  in,
		outStream: out,
		group:     group,
		name:      name,
		block:     time.Duration(blockSec) * time.Second,
		batch:     100,
		ctx:       ctx,
		cancel:    cancel,
	}
	c.client.XGroupCreateMkStream(ctx, in, group, "0")
	spool, err := transport.RuntimeSpoolFromEnv("dpi-engine-consumer")
	if err != nil {
		log.Printf("[redis] encrypted transport spool disabled: %v", err)
	}
	c.spool = spool
	return c
}

func (c *Consumer) Start() error {
	if !c.running.CompareAndSwap(false, true) {
		return nil
	}
	if err := c.client.Ping(c.ctx).Err(); err != nil {
		return fmt.Errorf("redis connect: %w", err)
	}
	if err := transport.RegisterProducer(c.ctx, c.client, "dpi-engine"); err != nil {
		return err
	}
	log.Printf("[redis] Connected")
	for i := 0; i < 4; i++ {
		c.wg.Add(1)
		go c.worker(i)
	}
	log.Printf("[redis] Started 4 workers")
	return nil
}

func (c *Consumer) Stop() {
	if !c.running.CompareAndSwap(true, false) {
		return
	}
	c.cancel()
	c.wg.Wait()
	c.client.Close()
	log.Println("[redis] Stopped")
}

func (c *Consumer) worker(id int) {
	defer c.wg.Done()
	consumerName := fmt.Sprintf("%s-%d", c.name, id)
	reliable := transport.NewRedisConsumer(transport.ConsumerConfig{
		Client: c.client, Group: c.group, Consumer: consumerName, Spool: c.spool,
		Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
	})
	for {
		if c.ctx.Err() != nil {
			return
		}
		if err := transport.RegisterProducer(c.ctx, c.client, "dpi-engine"); err != nil {
			atomic.AddUint64(&c.stats.Errors, 1)
			continue
		}
		if err := reliable.Reclaim(c.ctx, c.inStream, c.handleDelivery); err != nil {
			atomic.AddUint64(&c.stats.Errors, 1)
			continue
		}
		streams, err := c.client.XReadGroup(c.ctx, &redis.XReadGroupArgs{
			Group:    c.group,
			Consumer: consumerName,
			Streams:  []string{c.inStream, ">"},
			Count:    c.batch,
			Block:    c.block,
		}).Result()
		if err != nil || len(streams) == 0 {
			continue
		}
		if err := reliable.Handle(c.ctx, c.inStream, streams[0].Messages, c.handleDelivery); err != nil {
			atomic.AddUint64(&c.stats.Errors, 1)
		}
	}
}

func (c *Consumer) handleDelivery(ctx context.Context, delivery transport.Delivery) (transport.DurableOutcome, error) {
	uid := transport.DeterministicUID("dpi_engine_receipts", delivery.Stream, delivery.MessageID)
	processed, err := c.client.HExists(ctx, "transport_reliability:dpi_engine", uid).Result()
	if err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("load DPI receipt: %w", err)
	}
	if processed {
		return transport.DurableOutcome{UID: uid, Sink: "dpi_engine_receipts"}, nil
	}
	message := XMessage{ID: delivery.MessageID, Values: delivery.Values}
	if c.onFlowReliable != nil {
		if err := c.onFlowReliable(ctx, message); err != nil {
			return transport.DurableOutcome{}, err
		}
	} else if c.onFlow != nil {
		c.onFlow(message)
	}
	if err := c.client.HSet(ctx, "transport_reliability:dpi_engine", uid, delivery.MessageID).Err(); err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("persist DPI receipt: %w", err)
	}
	atomic.AddUint64(&c.stats.Processed, 1)
	return transport.DurableOutcome{UID: uid, Sink: "dpi_engine_receipts"}, nil
}

func (c *Consumer) OnFlow(handler func(msg XMessage)) {
	c.onFlow = handler
}

func (c *Consumer) OnFlowReliable(handler func(context.Context, XMessage) error) {
	c.onFlowReliable = handler
}

func (c *Consumer) GetOutStream() string {
	return c.outStream
}

func (c *Consumer) GetClient() *redis.Client {
	return c.client
}

func (c *Consumer) GetContext() context.Context {
	return c.ctx
}

func (c *Consumer) Stats() (processed, alerts, errors uint64) {
	return atomic.LoadUint64(&c.stats.Processed),
		atomic.LoadUint64(&c.stats.Alerts),
		atomic.LoadUint64(&c.stats.Errors)
}

func (c *Consumer) TransportAccounting(ctx context.Context) (transport.AccountingSnapshot, error) {
	return transport.LoadAccounting(ctx, c.client, c.group)
}
