package transportreliability

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

func LoadAccounting(ctx context.Context, client *redis.Client, group string) (AccountingSnapshot, error) {
	if client == nil || group == "" {
		return AccountingSnapshot{}, fmt.Errorf("Redis client and consumer group are required")
	}
	base := "transport_reliability:accounting:" + safeName(group)
	pipe := client.Pipeline()
	received := pipe.HLen(ctx, base+":seen")
	materialized := pipe.HLen(ctx, base+":materialized")
	spooled := pipe.HLen(ctx, base+":spooled")
	deadlettered := pipe.HLen(ctx, base+":deadlettered")
	pending := pipe.HLen(ctx, base+":pending")
	losses := pipe.HLen(ctx, base+":losses")
	if _, err := pipe.Exec(ctx); err != nil {
		return AccountingSnapshot{}, fmt.Errorf("load durable transport accounting: %w", err)
	}
	return AccountingSnapshot{Received: uint64(received.Val()), Materialized: uint64(materialized.Val()), Spooled: uint64(spooled.Val()), Deadlettered: uint64(deadlettered.Val()), Pending: uint64(pending.Val()), Losses: uint64(losses.Val())}, nil
}

func (consumer *RedisConsumer) accountingBase() string {
	return "transport_reliability:accounting:" + safeName(consumer.group)
}

func accountingDeliveryKey(delivery Delivery) string {
	return delivery.Stream + "\x00" + delivery.MessageID
}

func (consumer *RedisConsumer) beginAccounting(ctx context.Context, delivery Delivery) (bool, error) {
	base := consumer.accountingBase()
	result, err := consumer.client.Eval(ctx, accountingBeginScript, []string{base + ":seen", base + ":pending", base + ":materialized", base + ":spooled", base + ":deadlettered"}, accountingDeliveryKey(delivery)).Int64()
	if err != nil {
		return false, fmt.Errorf("begin durable transport accounting: %w", err)
	}
	return result == 1, nil
}

func (consumer *RedisConsumer) markLoss(ctx context.Context, delivery Delivery) error {
	base := consumer.accountingBase()
	if err := consumer.client.HSet(ctx, base+":losses", accountingDeliveryKey(delivery), 1).Err(); err != nil {
		return fmt.Errorf("mark durable transport loss: %w", err)
	}
	return nil
}

func (consumer *RedisConsumer) resolveAccounting(ctx context.Context, delivery Delivery, resolution string) error {
	base := consumer.accountingBase()
	key := accountingDeliveryKey(delivery)
	if err := consumer.client.Eval(ctx, accountingResolveScript, []string{base + ":pending", base + ":losses", base + ":materialized", base + ":spooled", base + ":deadlettered"}, key, resolution).Err(); err != nil {
		return fmt.Errorf("resolve durable transport accounting: %w", err)
	}
	return nil
}

const accountingBeginScript = `
local first = redis.call('HSETNX', KEYS[1], ARGV[1], 1)
if redis.call('HEXISTS', KEYS[3], ARGV[1]) == 0 and redis.call('HEXISTS', KEYS[4], ARGV[1]) == 0 and redis.call('HEXISTS', KEYS[5], ARGV[1]) == 0 then
  redis.call('HSET', KEYS[2], ARGV[1], 1)
end
return first
`

const accountingResolveScript = `
local target = 3
if ARGV[2] == 'spooled' then target = 4 end
if ARGV[2] == 'deadlettered' then target = 5 end
if redis.call('HEXISTS', KEYS[3], ARGV[1]) == 0 and redis.call('HEXISTS', KEYS[4], ARGV[1]) == 0 and redis.call('HEXISTS', KEYS[5], ARGV[1]) == 0 then
  redis.call('HSET', KEYS[target], ARGV[1], 1)
end
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
return 1
`
