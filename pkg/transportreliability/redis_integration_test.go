package transportreliability

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisConsumerInterruptionBeforeAckReclaimsToOneDurableUID(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	const stream = "todo7:events"
	const group = "todo7-group"
	if err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil {
		t.Fatalf("create group: %v", err)
	}
	messageID, err := client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"data": `{"id":"native-1"}`}}).Result()
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	messages, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: "first", Streams: []string{stream, ">"}, Count: 1}).Result()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	uid := DeterministicUID("threat_events", stream, messageID)
	consumer := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "first", Retry: RetryPolicy{MaxAttempts: 1}, ClaimIdle: time.Millisecond})
	consumer.beforeAck = func(context.Context, Delivery) error {
		pauseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return client.ClientPause(pauseCtx, 250*time.Millisecond).Err()
	}
	handler := func(ctx context.Context, delivery Delivery) (DurableOutcome, error) {
		if err := client.HSetNX(ctx, "todo7:sink", uid, delivery.MessageID).Err(); err != nil {
			return DurableOutcome{}, err
		}
		return DurableOutcome{UID: uid, Sink: "threat_events"}, nil
	}

	// When
	ackCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	err = consumer.Handle(ackCtx, stream, messages[0].Messages, handler)
	cancel()
	if err == nil {
		t.Fatal("Redis pause did not interrupt ACK")
	}
	awaitRedis(t, client)
	consumer.beforeAck = nil
	consumer.consumer = "recovery"
	if err := consumer.Reclaim(ctx, stream, handler); err != nil {
		t.Fatalf("reclaim pending delivery: %v", err)
	}

	// Then
	count, err := client.HLen(ctx, "todo7:sink").Result()
	if err != nil || count != 1 {
		t.Fatalf("durable UID materialized %d times: %v", count, err)
	}
	pending, err := client.XPending(ctx, stream, group).Result()
	if err != nil || pending.Count != 0 {
		t.Fatalf("reclaimed message remained pending: %+v %v", pending, err)
	}
}

func TestRedisProducerCrashAfterPublishReplaysSameDownstreamUID(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: t.TempDir(), Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	producer, err := NewRedisProducer(ProducerConfig{Client: client, Name: "agent-traffic", Retry: RetryPolicy{MaxAttempts: 2}, Spool: spool})
	if err != nil {
		t.Fatalf("create producer: %v", err)
	}
	crashed := false
	spool.afterDeliver = func(SpoolRecord) error {
		if !crashed {
			crashed = true
			return errors.New("simulated crash after XADD")
		}
		return nil
	}

	// When
	firstErr := producer.Publish(ctx, "todo7:producer-crash", "native-record-1", map[string]interface{}{"data": "payload"})
	secondErr := producer.Replay(ctx)

	// Then
	messages, err := client.XRange(ctx, "todo7:producer-crash", "-", "+").Result()
	uniqueUIDs := make(map[interface{}]struct{})
	for _, message := range messages {
		uniqueUIDs[message.Values["event_uid"]] = struct{}{}
	}
	if firstErr == nil || secondErr != nil || err != nil || len(messages) != 2 || len(uniqueUIDs) != 1 {
		t.Fatalf("crash replay produced distinct downstream UID: first=%v second=%v messages=%+v unique=%v read=%v", firstErr, secondErr, messages, uniqueUIDs, err)
	}
}

func TestRedisConsumerPermanentFailurePersistsNamedDeadLetterReason(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	const stream = "todo7:invalid"
	const group = "todo7-invalid"
	if err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"data": "{"}}).Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	read, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: "worker", Streams: []string{stream, ">"}, Count: 1}).Result()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	consumer := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "worker", Retry: RetryPolicy{MaxAttempts: 3}})

	// When
	err = consumer.Handle(ctx, stream, read[0].Messages, func(context.Context, Delivery) (DurableOutcome, error) {
		return DurableOutcome{}, Permanent(ReasonInvalidPayload, errors.New("invalid JSON"))
	})

	// Then
	if err != nil {
		t.Fatalf("dead-letter handoff failed: %v", err)
	}
	letters, err := client.XRange(ctx, "deadletter:"+stream, "-", "+").Result()
	if err != nil || len(letters) != 1 || letters[0].Values["reason"] != string(ReasonInvalidPayload) {
		t.Fatalf("dead-letter reason missing: %+v %v", letters, err)
	}
}

func TestRedisConsumerDeadLetterAckInterruptionDoesNotDuplicateXAdd(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	const stream = "todo7:deadletter-interruption"
	const group = "todo7-deadletter-interruption"
	if err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"data": "{"}}).Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	read, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: "first", Streams: []string{stream, ">"}, Count: 1}).Result()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	consumer := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "first", Retry: RetryPolicy{MaxAttempts: 1}, ClaimIdle: time.Millisecond})
	consumer.beforeAck = func(context.Context, Delivery) error {
		return errors.New("simulated interruption before ACK")
	}
	handler := func(context.Context, Delivery) (DurableOutcome, error) {
		return DurableOutcome{}, Permanent(ReasonInvalidPayload, errors.New("invalid JSON"))
	}

	// When
	firstErr := consumer.Handle(ctx, stream, read[0].Messages, handler)
	consumer.beforeAck = nil
	consumer.consumer = "recovery"
	reclaimErr := consumer.Reclaim(ctx, stream, handler)

	// Then
	letters, err := client.XRange(ctx, "deadletter:"+stream, "-", "+").Result()
	if firstErr == nil || reclaimErr != nil || err != nil || len(letters) != 1 {
		t.Fatalf("dead-letter ACK interruption duplicated durable record: first=%v reclaim=%v letters=%+v read=%v", firstErr, reclaimErr, letters, err)
	}
}

func TestRedisConsumerAccountingCountsUniquePendingAcrossRestartAndReclaim(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	const stream = "todo7:accounting-restart"
	const group = "todo7-accounting-restart"
	if err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"data": "payload"}}).Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	read, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: "first", Streams: []string{stream, ">"}, Count: 1}).Result()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	uid := DeterministicUID("accounting_sink", stream, read[0].Messages[0].ID)
	handler := func(ctx context.Context, delivery Delivery) (DurableOutcome, error) {
		if err := client.HSetNX(ctx, "todo7:accounting-sink", uid, delivery.MessageID).Err(); err != nil {
			return DurableOutcome{}, err
		}
		return DurableOutcome{UID: uid, Sink: "accounting_sink"}, nil
	}
	first := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "first", Retry: RetryPolicy{MaxAttempts: 1}, ClaimIdle: time.Millisecond})
	first.beforeAck = func(context.Context, Delivery) error { return errors.New("restart before ACK") }
	if err := first.Handle(ctx, stream, read[0].Messages, handler); err == nil {
		t.Fatal("first consumer did not stop before ACK")
	}
	second := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "second", Retry: RetryPolicy{MaxAttempts: 1}, ClaimIdle: time.Millisecond})

	// When
	if err := second.Reclaim(ctx, stream, handler); err != nil {
		t.Fatalf("reclaim after restart: %v", err)
	}
	snapshot, err := second.AccountingContext(ctx)

	// Then
	metrics := snapshot.Metrics()
	if err != nil || !snapshot.Valid() || snapshot.Received != 1 || snapshot.Materialized != 1 || snapshot.Pending != 0 || metrics["lyflow_transport_pending"] != 0 {
		t.Fatalf("restart accounting was not unique or exposed: snapshot=%+v metrics=%v err=%v", snapshot, metrics, err)
	}
}

func TestRedisHorizonPersistsAcrossStoreInstances(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	now := time.Now().UTC().Truncate(time.Second)
	first := NewRedisHorizonStore(client)
	record := HorizonRecord{MaximumSpoolRetryHorizon: 24 * time.Hour, ZeroLegacyReadsSince: now.Add(-24 * time.Hour), AllProducersUpgraded: false, PersistedAt: now}

	// When
	if err := first.Persist(ctx, record); err != nil {
		t.Fatalf("persist horizon: %v", err)
	}
	_, err := NewRedisHorizonStore(client).Load(ctx)

	// Then
	if err != nil {
		t.Fatalf("load persisted horizon: %v", err)
	}
}

func TestRedisHorizonRequiresCurrentVersionUnexpiredFullHorizonRegistrations(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	now := time.Now().UTC().Truncate(time.Second)
	maximum := 24 * time.Hour
	for _, producer := range RequiredProducers() {
		registration := ProducerRegistration{Name: producer, Version: ProducerProtocolVersion, MaximumSpoolRetryHorizon: maximum, RegisteredAt: now, ExpiresAt: now.Add(ProducerLeaseTTL)}
		if err := RegisterProducerEvidence(ctx, client, registration); err != nil {
			t.Fatalf("register producer %s: %v", producer, err)
		}
	}
	store := NewRedisHorizonStore(client)

	// When
	current, currentErr := store.AllProducersUpgradedAt(ctx, maximum, now)
	expired, expiredErr := store.AllProducersUpgradedAt(ctx, maximum, now.Add(ProducerLeaseTTL+time.Second))
	short, shortErr := store.AllProducersUpgradedAt(ctx, maximum+time.Second, now)

	// Then
	if currentErr != nil || expiredErr != nil || shortErr != nil || !current || expired || short {
		t.Fatalf("producer registration proof was not versioned, expiring, and horizon-complete: current=%v expired=%v short=%v errors=%v/%v/%v", current, expired, short, currentErr, expiredErr, shortErr)
	}
}

func TestRedisHorizonRefreshDoesNotFreshenWithoutNewObservation(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	store := NewRedisHorizonStore(client)
	observedAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	observation := HorizonObservation{MaximumSpoolRetryHorizon: time.Hour, LegacyRead: false, ObservedAt: observedAt}
	if err := store.RefreshObservation(ctx, observation, observedAt); err != nil {
		t.Fatalf("persist first observation: %v", err)
	}

	// When
	if err := store.RefreshObservation(ctx, observation, observedAt.Add(30*time.Minute)); err != nil {
		t.Fatalf("refresh duplicate observation: %v", err)
	}
	record, err := store.LoadRecord(ctx)

	// Then
	if err != nil || !record.PersistedAt.Equal(observedAt) || !record.ZeroLegacyReadsSince.Equal(observedAt) {
		t.Fatalf("duplicate observation freshened old horizon: %+v err=%v", record, err)
	}
}

func TestRedisConsumerExhaustionSpoolsAndDeadlettersWithoutSilentDrop(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	const stream = "todo7:exhaustion"
	const group = "todo7-exhaustion"
	if err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"data": "payload"}}).Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	read, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: "worker", Streams: []string{stream, ">"}, Count: 1}).Result()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: t.TempDir(), Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	consumer := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "worker", Retry: RetryPolicy{MaxAttempts: 2}, Spool: spool})

	// When
	err = consumer.Handle(ctx, stream, read[0].Messages, func(context.Context, Delivery) (DurableOutcome, error) {
		return DurableOutcome{}, errors.New("sink unavailable")
	})

	// Then
	if err != nil {
		t.Fatalf("durable exhaustion handoff failed: %v", err)
	}
	snapshot := consumer.Accounting()
	if !snapshot.Valid() || snapshot.Spooled != 1 || snapshot.Losses != 0 {
		t.Fatalf("exhaustion was silently dropped: %+v", snapshot)
	}
}

func TestRedisConsumerFullSpoolLeavesPendingAndIncrementsLossMetric(t *testing.T) {
	// Given
	client, ctx := testRedis(t)
	const stream = "todo7:full-spool"
	const group = "todo7-full-spool"
	if err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err(); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]interface{}{"data": "payload"}}).Err(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	read, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: group, Consumer: "worker", Streams: []string{stream, ">"}, Count: 1}).Result()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: t.TempDir(), Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	consumer := NewRedisConsumer(ConsumerConfig{Client: client, Group: group, Consumer: "worker", Retry: RetryPolicy{MaxAttempts: 1}, Spool: spool})

	// When
	err = consumer.Handle(ctx, stream, read[0].Messages, func(context.Context, Delivery) (DurableOutcome, error) {
		return DurableOutcome{}, errors.New("sink unavailable")
	})

	// Then
	pending, pendingErr := client.XPending(ctx, stream, group).Result()
	snapshot := consumer.Accounting()
	if !errors.Is(err, ErrSpoolFull) || pendingErr != nil || pending.Count != 1 || snapshot.Losses != 1 || !snapshot.Valid() {
		t.Fatalf("full spool accounting failed: err=%v pending=%+v pendingErr=%v accounting=%+v", err, pending, pendingErr, snapshot)
	}
}

func testRedis(t *testing.T) (*redis.Client, context.Context) {
	t.Helper()
	address := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("LYFLOW_TEST_REDIS_ADDR is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{Addr: address, ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush Redis: %v", err)
	}
	return client, ctx
}

func awaitRedis(t *testing.T, client *redis.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if client.Ping(ctx).Err() == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("Redis did not recover: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}
