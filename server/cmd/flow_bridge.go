package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// runFlowBridge consumes flows:raw in its own consumer group. The main
// server-workers consumer also handles semantic sessions and alerts, but raw
// probe flows can grow into a very large backlog; a dedicated bridge keeps
// flows:raw advancing without starving session persistence.
func (c *ConsumerState) runFlowBridge() {
	if c == nil || c.cfg == nil || c.cfg.Redis == nil {
		return
	}
	ctx := context.Background()
	const group = "flow-bridge"
	const consumer = "flow-bridge"
	for {
		err := c.cfg.Redis.XGroupCreateMkStream(ctx, "flows:raw", group, "0").Err()
		if err == nil || strings.Contains(strings.ToUpper(err.Error()), "BUSYGROUP") {
			break
		}
		log.Printf("flow bridge group setup failed: %v", err)
		time.Sleep(time.Second)
	}
	for {
		result, err := c.cfg.Redis.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group: group, Consumer: consumer, Streams: []string{"flows:raw", ">"},
			Count: 200, Block: time.Second,
		}).Result()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			log.Printf("flow bridge read failed: %v", err)
			time.Sleep(time.Second)
			continue
		}
		for _, stream := range result {
			for _, message := range stream.Messages {
				if err := c.bridgeRawFlow(ctx, message); err != nil {
					log.Printf("flow bridge failed id=%s: %v", message.ID, err)
					continue
				}
				if err := c.cfg.Redis.XAck(ctx, "flows:raw", group, message.ID).Err(); err != nil {
					log.Printf("flow bridge ack failed id=%s: %v", message.ID, err)
				}
			}
		}
	}
}
