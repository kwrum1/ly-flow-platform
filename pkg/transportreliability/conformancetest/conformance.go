package conformancetest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type Sink struct {
	Stream        string
	UIDField      string
	UID           string
	DeliveryCount int
}

type Adapter struct {
	Name    string
	Publish func(context.Context) error
	Sinks   []Sink
}

type RedisHarness struct {
	Client  *redis.Client
	Context context.Context
}

func Redis(t testing.TB) RedisHarness {
	t.Helper()
	address := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("LYFLOW_TEST_REDIS_ADDR is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush disposable Redis: %v", err)
	}
	return RedisHarness{Client: client, Context: ctx}
}

func RunCrashReplay(t testing.TB, harness RedisHarness, adapter Adapter) {
	t.Helper()
	if err := adapter.Publish(harness.Context); err != nil {
		t.Fatalf("%s first publish: %v", adapter.Name, err)
	}
	if err := adapter.Publish(harness.Context); err != nil {
		t.Fatalf("%s crash replay: %v", adapter.Name, err)
	}
	for index, sink := range adapter.Sinks {
		messages, err := harness.Client.XRange(harness.Context, sink.Stream, "-", "+").Result()
		if err != nil {
			t.Fatalf("%s read %s: %v", adapter.Name, sink.Stream, err)
		}
		if len(messages) != sink.DeliveryCount {
			t.Fatalf("%s deliveries to %s = %d, want %d", adapter.Name, sink.Stream, len(messages), sink.DeliveryCount)
		}
		materialized := fmt.Sprintf("todo7:conformance:%s:%d", adapter.Name, index)
		for _, message := range messages {
			uid := fmt.Sprint(message.Values[sink.UIDField])
			if uid != sink.UID {
				t.Fatalf("%s changed UID in %s: got %q want %q", adapter.Name, sink.Stream, uid, sink.UID)
			}
			if err := harness.Client.HSetNX(harness.Context, materialized, uid, message.ID).Err(); err != nil {
				t.Fatalf("%s materialize %s: %v", adapter.Name, sink.Stream, err)
			}
		}
		outcomes, err := harness.Client.HLen(harness.Context, materialized).Result()
		if err != nil || outcomes != 1 {
			t.Fatalf("%s durable outcomes for %s = %d, want 1: %v", adapter.Name, sink.Stream, outcomes, err)
		}
	}
}
