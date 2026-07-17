package transportreliability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type ProducerConfig struct {
	Client *redis.Client
	Name   string
	Retry  RetryPolicy
	Spool  *EncryptedSpool
	Sleep  SleepFunc
}

func (producer *RedisProducer) PublishAuto(ctx context.Context, stream string, values map[string]interface{}) error {
	for _, field := range []string{"event_uid", "id", "record_uid"} {
		if value, ok := values[field].(string); ok && value != "" {
			return producer.Publish(ctx, stream, value, values)
		}
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return fmt.Errorf("encode producer identity: %w", err)
	}
	digest := sha256.Sum256(payload)
	return producer.Publish(ctx, stream, fmt.Sprintf("payload-%x", digest[:16]), values)
}

type RedisProducer struct {
	client *redis.Client
	name   string
	retry  RetryPolicy
	spool  *EncryptedSpool
	sleep  SleepFunc
}

func NewRedisProducer(config ProducerConfig) (*RedisProducer, error) {
	if config.Client == nil || config.Name == "" || config.Spool == nil {
		return nil, fmt.Errorf("Redis client, producer name, and encrypted spool are required")
	}
	return &RedisProducer{client: config.Client, name: config.Name, retry: config.Retry, spool: config.Spool, sleep: config.Sleep}, nil
}

func (producer *RedisProducer) Publish(ctx context.Context, stream, nativeID string, values map[string]interface{}) error {
	if stream == "" || nativeID == "" {
		return fmt.Errorf("stream and stable native ID are required")
	}
	payload, err := json.Marshal(values)
	if err != nil {
		return fmt.Errorf("encode producer payload: %w", err)
	}
	uid := DeterministicUID(producer.name, stream, nativeID)
	if err := producer.spool.Append(ctx, SpoolRecord{UID: uid, Stream: stream, MessageID: nativeID, Payload: payload}); err != nil {
		return fmt.Errorf("durably spool producer record %s: %w", uid, err)
	}
	return producer.Replay(ctx)
}

func (producer *RedisProducer) Replay(ctx context.Context) error {
	return producer.spool.Replay(ctx, producer.deliver)
}

func (producer *RedisProducer) deliver(ctx context.Context, record SpoolRecord) error {
	var values map[string]interface{}
	if err := json.Unmarshal(record.Payload, &values); err != nil {
		return fmt.Errorf("decode producer record %s: %w", record.UID, err)
	}
	values["event_uid"] = record.UID
	if err := producer.retry.Do(ctx, record.UID, func(attemptCtx context.Context) error {
		if err := RegisterProducer(attemptCtx, producer.client, producer.name); err != nil {
			return err
		}
		return producer.client.XAdd(attemptCtx, &redis.XAddArgs{Stream: record.Stream, Values: values}).Err()
	}, producer.sleep); err != nil {
		return fmt.Errorf("publish durable producer record %s: %w", record.UID, err)
	}
	return nil
}
