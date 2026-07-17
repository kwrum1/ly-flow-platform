package transportreliability

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"
)

type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	Jitter      float64
}

type SleepFunc func(context.Context, time.Duration) error

func (policy RetryPolicy) Do(ctx context.Context, key string, operation func(context.Context) error, sleep SleepFunc) error {
	attempts := policy.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	if sleep == nil {
		sleep = sleepContext
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := operation(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt == attempts {
			break
		}
		if err := sleep(ctx, policy.delay(key, attempt)); err != nil {
			return fmt.Errorf("retry wait: %w", err)
		}
	}
	return fmt.Errorf("retry exhausted after %d attempts: %w", attempts, lastErr)
}

func (policy RetryPolicy) delay(key string, attempt int) time.Duration {
	delay := policy.BaseDelay
	if delay <= 0 {
		return 0
	}
	for index := 1; index < attempt; index++ {
		if policy.MaxDelay > 0 && delay >= policy.MaxDelay/2 {
			delay = policy.MaxDelay
			break
		}
		delay *= 2
	}
	if policy.MaxDelay > 0 && delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}
	if policy.Jitter <= 0 {
		return delay
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(fmt.Sprintf("%s:%d", key, attempt)))
	unit := float64(hash.Sum64()%10001) / 10000
	factor := 1 - policy.Jitter + (2 * policy.Jitter * unit)
	jittered := time.Duration(float64(delay) * factor)
	if jittered < 0 {
		return 0
	}
	if policy.MaxDelay > 0 && jittered > policy.MaxDelay {
		return policy.MaxDelay
	}
	return jittered
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
