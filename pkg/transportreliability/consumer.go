package transportreliability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Delivery struct {
	Stream    string
	MessageID string
	Values    map[string]interface{}
}

type DurableOutcome struct {
	UID  string
	Sink string
}

type Handler func(context.Context, Delivery) (DurableOutcome, error)

type ConsumerConfig struct {
	Client    *redis.Client
	Group     string
	Consumer  string
	Retry     RetryPolicy
	Spool     *EncryptedSpool
	ClaimIdle time.Duration
	ClaimSize int64
	Sleep     SleepFunc
}

type RedisConsumer struct {
	client    *redis.Client
	group     string
	consumer  string
	retry     RetryPolicy
	spool     *EncryptedSpool
	claimIdle time.Duration
	claimSize int64
	sleep     SleepFunc
	stats     Accounting
	beforeAck func(context.Context, Delivery) error
}

func NewRedisConsumer(config ConsumerConfig) *RedisConsumer {
	claimIdle := config.ClaimIdle
	if claimIdle <= 0 {
		claimIdle = 30 * time.Second
	}
	claimSize := config.ClaimSize
	if claimSize <= 0 {
		claimSize = 100
	}
	return &RedisConsumer{
		client: config.Client, group: config.Group, consumer: config.Consumer,
		retry: config.Retry, spool: config.Spool, claimIdle: claimIdle,
		claimSize: claimSize, sleep: config.Sleep,
	}
}

func (consumer *RedisConsumer) Handle(ctx context.Context, stream string, messages []redis.XMessage, handler Handler) error {
	if consumer.client == nil {
		return fmt.Errorf("Redis consumer client is required")
	}
	for _, message := range messages {
		delivery := Delivery{Stream: stream, MessageID: message.ID, Values: message.Values}
		first, err := consumer.beginAccounting(ctx, delivery)
		if err != nil {
			return err
		}
		if first {
			consumer.stats.Received()
		}
		resolution, err := consumer.handoff(ctx, delivery, handler)
		if err != nil {
			if accountingErr := consumer.markLoss(ctx, delivery); accountingErr != nil {
				return errors.Join(err, accountingErr)
			}
			if first {
				consumer.stats.Lost()
			}
			return err
		}
		if err := consumer.resolveAccounting(ctx, delivery, resolution); err != nil {
			return err
		}
		if first {
			switch resolution {
			case "materialized":
				consumer.stats.Materialized()
			case "spooled":
				consumer.stats.Spooled()
			case "deadlettered":
				consumer.stats.Deadlettered()
			}
		}
		if consumer.beforeAck != nil {
			if err := consumer.beforeAck(ctx, delivery); err != nil {
				return fmt.Errorf("before ACK %s: %w", delivery.MessageID, err)
			}
		}
		if err := consumer.client.XAck(ctx, stream, consumer.group, message.ID).Err(); err != nil {
			return fmt.Errorf("ACK %s/%s: %w", stream, message.ID, err)
		}
	}
	return nil
}

func (consumer *RedisConsumer) Reclaim(ctx context.Context, stream string, handler Handler) error {
	start := "0-0"
	for {
		messages, next, err := consumer.client.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream: stream, Group: consumer.group, Consumer: consumer.consumer,
			MinIdle: consumer.claimIdle, Start: start, Count: consumer.claimSize,
		}).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			return fmt.Errorf("reclaim pending stream %s: %w", stream, err)
		}
		if len(messages) > 0 {
			if err := consumer.Handle(ctx, stream, messages, handler); err != nil {
				return err
			}
		}
		if next == "0-0" || len(messages) == 0 {
			return nil
		}
		start = next
	}
}

func (consumer *RedisConsumer) Accounting() AccountingSnapshot {
	return consumer.stats.Snapshot()
}

func (consumer *RedisConsumer) AccountingContext(ctx context.Context) (AccountingSnapshot, error) {
	return LoadAccounting(ctx, consumer.client, consumer.group)
}

func (consumer *RedisConsumer) handoff(ctx context.Context, delivery Delivery, handler Handler) (string, error) {
	if handler == nil {
		return "", fmt.Errorf("delivery handler is required")
	}
	err := consumer.retry.Do(ctx, delivery.MessageID, func(attemptCtx context.Context) error {
		result, err := handler(attemptCtx, delivery)
		if err != nil {
			return err
		}
		if result.UID == "" || result.Sink == "" {
			return Permanent(ReasonHandlerRejected, errors.New("handler returned no durable UID or sink"))
		}
		return nil
	}, consumer.sleep)
	if err == nil {
		return "materialized", nil
	}
	var permanent *permanentError
	if errors.As(err, &permanent) {
		if deadErr := consumer.deadLetter(ctx, delivery, permanent.reason, permanent.cause); deadErr != nil {
			return "", errors.Join(err, deadErr)
		}
		return "deadlettered", nil
	}
	if consumer.spool != nil {
		payload, encodeErr := json.Marshal(delivery.Values)
		if encodeErr != nil {
			return "", errors.Join(err, fmt.Errorf("encode retry spool payload: %w", encodeErr))
		}
		record := SpoolRecord{
			UID:    DeterministicUID("transport_spool", delivery.Stream, delivery.MessageID),
			Stream: delivery.Stream, MessageID: delivery.MessageID, Payload: payload,
			Reason: string(ReasonRetryExhausted), CreatedAt: time.Now().UTC(),
		}
		if spoolErr := consumer.spool.Append(ctx, record); spoolErr != nil {
			return "", errors.Join(err, spoolErr)
		}
		return "spooled", nil
	}
	if deadErr := consumer.deadLetter(ctx, delivery, ReasonRetryExhausted, err); deadErr != nil {
		return "", errors.Join(err, deadErr)
	}
	return "deadlettered", nil
}
