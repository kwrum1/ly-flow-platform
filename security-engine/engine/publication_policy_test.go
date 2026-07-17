package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
)

var errControlHealthExportUnavailable = errors.New("control health export unavailable")

type controlHealthPublicationHook struct {
	failing atomic.Bool
}

func (hook *controlHealthPublicationHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (hook *controlHealthPublicationHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() != "xadd" {
			return next(ctx, cmd)
		}
		if hook.failing.Load() {
			return errControlHealthExportUnavailable
		}
		published, ok := cmd.(*redis.StringCmd)
		if !ok {
			return next(ctx, cmd)
		}
		published.SetVal("1-0")
		return nil
	}
}

func (hook *controlHealthPublicationHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestPublishControlHealth_failure_and_recovery_preserve_prevention_on_production_path(t *testing.T) {
	// Given
	hook := &controlHealthPublicationHook{}
	hook.failing.Store(true)
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.AddHook(hook)
	eng := New(config.Config{ControlHealthStream: "control:health"}, client)

	// When
	publishErr := eng.publishControlHealth(context.Background(), eng.RuntimeHealth())
	failed := eng.RuntimeHealth()
	hook.failing.Store(false)
	recoveryErr := eng.publishControlHealth(context.Background(), failed)
	recovered := eng.RuntimeHealth()

	// Then
	var typedErr *ControlHealthPublicationError
	if !errors.As(publishErr, &typedErr) {
		t.Fatalf("publication error = %T %v, want typed publication failure", publishErr, publishErr)
	}
	if failed.Status != controlHealthDegraded || failed.Reason != "control_health_delivery_unavailable" || !failed.PreventionEnabled {
		t.Fatalf("publication failure did not remain fail open: %+v", failed)
	}
	if failed.Publication.Status != controlHealthDegraded || failed.Publication.RetryCount != 3 || failed.Publication.LastError == "" {
		t.Fatalf("publication failure health metric = %+v", failed.Publication)
	}
	if recoveryErr != nil {
		t.Fatalf("publication recovery error = %v", recoveryErr)
	}
	if recovered.Status != controlHealthHealthy || !recovered.PreventionEnabled {
		t.Fatalf("publication recovery did not restore observation health: %+v", recovered)
	}
	if recovered.Publication.Status != controlHealthHealthy || recovered.Publication.RetryCount != 3 || recovered.Publication.LastError != "" {
		t.Fatalf("publication recovery health metric = %+v", recovered.Publication)
	}
}

func TestPublishControlHealth_failure_does_not_override_integrity_fail_closed(t *testing.T) {
	// Given
	hook := &controlHealthPublicationHook{}
	hook.failing.Store(true)
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.AddHook(hook)
	eng := New(config.Config{RuleTrustRoot: "/missing/root.pem", ControlHealthStream: "control:health"}, client)

	// When
	health, err := eng.VerifyIntegrity(context.Background())
	hook.failing.Store(false)
	recoveryErr := eng.publishControlHealth(context.Background(), health)
	recovered := eng.RuntimeHealth()

	// Then
	var publishErr *ControlHealthPublicationError
	if !errors.Is(err, ErrLifecycleManifest) || !errors.As(err, &publishErr) {
		t.Fatalf("integrity error = %T %v, want integrity and typed publication failures", err, err)
	}
	if health.Reason != "config_or_binary_integrity_failed" || health.PreventionEnabled {
		t.Fatalf("publication failure overrode integrity fail closed: %+v", health)
	}
	if health.Publication.Status != controlHealthDegraded || health.Publication.RetryCount != 3 {
		t.Fatalf("publication failure metric = %+v", health.Publication)
	}
	if recoveryErr != nil {
		t.Fatalf("publication recovery error = %v", recoveryErr)
	}
	if recovered.Reason != "config_or_binary_integrity_failed" || recovered.PreventionEnabled {
		t.Fatalf("publication recovery overrode integrity fail closed: %+v", recovered)
	}
	if recovered.Publication.Status != controlHealthHealthy || recovered.Publication.RetryCount != 3 {
		t.Fatalf("publication recovery metric = %+v", recovered.Publication)
	}
}
