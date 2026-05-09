package redis

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

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
	stats     struct{ Processed uint64; Alerts uint64; Errors uint64 }
	onFlow    func(msg XMessage)
}

type XMessage struct {
	ID     string
	Values map[string]interface{}
}

func NewConsumer(addr, pass string, db int, in, out, group, name string, workers int, blockSec int) *Consumer {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Consumer{
		client:    redis.NewClient(&redis.Options{Addr: addr, Password: pass, DB: db}),
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
	return c
}

func (c *Consumer) Start() error {
	if !c.running.CompareAndSwap(false, true) {
		return nil
	}
	if err := c.client.Ping(c.ctx).Err(); err != nil {
		return fmt.Errorf("redis connect: %w", err)
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
	for {
		if c.ctx.Err() != nil {
			return
		}
		streams, err := c.client.XReadGroup(c.ctx, &redis.XReadGroupArgs{
			Group:    c.group,
			Consumer: fmt.Sprintf("%s-%d", c.name, id),
			Streams:  []string{c.inStream, ">"},
			Count:    c.batch,
			Block:    c.block,
		}).Result()
		if err != nil || len(streams) == 0 {
			continue
		}
		for _, msg := range streams[0].Messages {
			atomic.AddUint64(&c.stats.Processed, 1)
			xmsg := XMessage{
				ID:     msg.ID,
				Values: msg.Values,
			}
			if c.onFlow != nil {
				c.onFlow(xmsg)
			}
			c.client.XAck(c.ctx, c.inStream, c.group, msg.ID)
		}
	}
}

func (c *Consumer) OnFlow(handler func(msg XMessage)) {
	c.onFlow = handler
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