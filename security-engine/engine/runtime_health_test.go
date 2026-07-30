package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
)

func TestRuntimeHealth_reports_limits_and_fail_policy_for_security_engine(t *testing.T) {
	// Given
	cfg := config.Config{ReadCount: 64, MaxMessageBytes: 1024, CPUBudget: 100 * time.Millisecond, MemoryBudgetBytes: 4096, RestartBudget: 3}
	eng := New(cfg, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))

	// When
	health := eng.RuntimeHealth()

	// Then
	if health.SchemaVersion != controlHealthSchemaVersion || health.FailPolicy.Observation != failOpen || health.FailPolicy.Integrity != failClosed || health.FailPolicy.Authorization != failClosed {
		t.Fatalf("unexpected security-engine health: %+v", health)
	}
	if health.Limits.QueueCapacity != 64 || health.Limits.MemoryBytes != 4096 || health.Limits.RestartBudget != 3 {
		t.Fatalf("unexpected security-engine limits: %+v", health.Limits)
	}
}

func TestRuntimeHealth_transport_outage_is_degraded_fail_open(t *testing.T) {
	// Given
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond})
	eng := New(config.Config{InputStreams: []string{"telemetry:runtime"}, ConsumerGroup: "health", ConsumerName: "health-1", ReadCount: 1, ReadBlock: time.Millisecond, MaxMessageBytes: 1024, CPUBudget: time.Second, MemoryBudgetBytes: 4096, RestartBudget: 3}, client)

	// When
	eng.consumeOnce(context.Background())
	health := eng.RuntimeHealth()

	// Then
	if health.Status != controlHealthDegraded || health.Reason != "transport_unavailable" || !health.PreventionEnabled {
		t.Fatalf("transport outage did not fail open: %+v", health)
	}
}

func TestRuntimeHealth_manifest_tamper_disables_prevention_and_emits_event(t *testing.T) {
	// Given
	manifestPath, rootPath, bundleRoot, _ := writeSignedLifecycleFixture(t)
	bundle, manifest, err := LoadLifecycleBundle(manifestPath, rootPath, bundleRoot)
	if err != nil {
		t.Fatalf("load fixture lifecycle: %v", err)
	}
	eng := New(config.Config{LifecycleManifest: manifestPath, RuleTrustRoot: rootPath, BundleRoot: bundleRoot, MaxMessageBytes: 1024, CPUBudget: time.Second, MemoryBudgetBytes: 4096, RestartBudget: 3}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	eng.Activate(bundle, manifest)
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, append(contents, []byte(`{}`)...), 0o600); err != nil {
		t.Fatalf("tamper manifest: %v", err)
	}

	// When
	event, verifyErr := eng.VerifyIntegrity(context.Background())

	// Then
	if verifyErr == nil || !errors.Is(verifyErr, ErrLifecycleManifest) {
		t.Fatalf("tamper verification error = %v", verifyErr)
	}
	if event.SchemaVersion != controlHealthSchemaVersion || event.Status != controlHealthDegraded || event.PreventionEnabled {
		t.Fatalf("tamper event did not fail closed: %+v", event)
	}
}

func TestProcess_rejects_message_over_memory_budget(t *testing.T) {
	// Given
	eng := New(config.Config{MaxMessageBytes: 8, CPUBudget: time.Second, MemoryBudgetBytes: 8, RestartBudget: 3}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	delivery := transport.Delivery{Stream: "telemetry:runtime", MessageID: "1-0", Values: map[string]any{"data": "123456789"}}

	// When
	_, err := eng.process(context.Background(), delivery)

	// Then
	if !errors.Is(err, ErrRuntimeMemoryBudget) {
		t.Fatalf("message budget error = %v, want ErrRuntimeMemoryBudget", err)
	}
}

func TestRuntimeHealth_restart_budget_exhaustion_fails_closed(t *testing.T) {
	// Given
	eng := New(config.Config{RestartBudget: 1}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))

	// When
	first := eng.RecordWatchdogRestart()
	second := eng.RecordWatchdogRestart()

	// Then
	if !first || second {
		t.Fatalf("restart decisions first=%v second=%v", first, second)
	}
	health := eng.RuntimeHealth()
	if health.Status != controlHealthDegraded || health.Reason != "restart_budget_exhausted" || health.PreventionEnabled {
		t.Fatalf("restart exhaustion did not fail closed: %+v", health)
	}
}

func TestRuntimeHealth_stale_watchdog_degrades_observation_fail_open(t *testing.T) {
	// Given
	eng := New(config.Config{}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	eng.health.mu.Lock()
	eng.health.watchdogAt = time.Now().Add(-time.Minute)
	eng.health.mu.Unlock()

	// When
	healthy := eng.health.checkWatchdog(time.Second)
	health := eng.RuntimeHealth()

	// Then
	if healthy || health.Status != controlHealthDegraded || health.Reason != "watchdog_stale" || !health.PreventionEnabled {
		t.Fatalf("stale watchdog did not fail open: %+v", health)
	}
}

func TestVerifyIntegrity_partial_signed_runtime_configuration_fails_closed(t *testing.T) {
	// Given
	eng := New(config.Config{RuleTrustRoot: "/missing/root.pem"}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))

	// When
	health, err := eng.VerifyIntegrity(context.Background())

	// Then
	if !errors.Is(err, ErrLifecycleManifest) {
		t.Fatalf("partial integrity configuration error = %v", err)
	}
	if health.Reason != "config_or_binary_integrity_failed" || health.PreventionEnabled {
		t.Fatalf("partial integrity configuration did not fail closed: %+v", health)
	}
}

func TestSnapshotContext_propagates_integrity_and_health_publication_failures(t *testing.T) {
	// Given
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond})
	eng := New(config.Config{
		RuleTrustRoot:       "/missing/root.pem",
		ControlHealthStream: "telemetry:runtime",
	}, client)

	// When
	snapshot, err := eng.SnapshotContext(context.Background())

	// Then
	var snapshotErr *SnapshotError
	var publishErr *ControlHealthPublicationError
	if !errors.As(err, &snapshotErr) || !errors.Is(err, ErrLifecycleManifest) || !errors.As(err, &publishErr) {
		t.Fatalf("snapshot error = %T %v, want typed integrity and publication failures", err, err)
	}
	if snapshot.ControlHealth.Status != controlHealthDegraded || snapshot.ControlHealth.PreventionEnabled {
		t.Fatalf("snapshot did not fail closed: %+v", snapshot.ControlHealth)
	}
}

func TestRuntimeHealth_emits_canonical_control_health_fields(t *testing.T) {
	// Given
	eng := New(config.Config{ReadCount: 64, MaxMessageBytes: 1024, CPUBudget: 100 * time.Millisecond, MemoryBudgetBytes: 4096, RestartBudget: 3}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))

	// When
	encoded, err := json.Marshal(eng.RuntimeHealth())
	if err != nil {
		t.Fatalf("marshal runtime health: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode runtime health fields: %v", err)
	}
	var limits map[string]json.RawMessage
	if err := json.Unmarshal(fields["limits"], &limits); err != nil {
		t.Fatalf("decode runtime limits: %v", err)
	}

	// Then
	wantFields := []string{"schema_version", "event_type", "runtime", "status", "reason", "prevention_enabled", "fail_policy", "limits", "restart_count", "watchdog_at", "publication"}
	if len(fields) != len(wantFields) {
		t.Fatalf("control-health field count = %d, want fields %v", len(fields), wantFields)
	}
	for _, field := range wantFields {
		if _, ok := fields[field]; !ok {
			t.Fatalf("control-health field %q missing", field)
		}
	}
	wantLimits := []string{"queue_capacity", "read_bytes", "cpu_budget_ms", "memory_bytes", "restart_budget"}
	if len(limits) != len(wantLimits) {
		t.Fatalf("limit field count = %d, want fields %v", len(limits), wantLimits)
	}
	for _, field := range wantLimits {
		if _, ok := limits[field]; !ok {
			t.Fatalf("limit field %q missing", field)
		}
	}
}

func TestRuntimeHealth_matches_shared_canonical_fixture_bytes(t *testing.T) {
	// Given
	eng := New(config.Config{ReadCount: 128, MaxMessageBytes: 1 << 20, CPUBudget: 1000 * time.Millisecond, MemoryBudgetBytes: 256 << 10, RestartBudget: 3}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"}))
	eng.health.mu.Lock()
	eng.health.status = controlHealthDegraded
	eng.health.reason = "control_health_delivery_unavailable"
	eng.health.restartCount = 2
	eng.health.watchdogAt = time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	eng.health.publication = ControlHealthPublicationSnapshot{Status: controlHealthDegraded, RetryCount: 3, LastError: "fixture publication unavailable"}
	eng.health.mu.Unlock()
	snapshot := eng.RuntimeHealth()
	snapshot.Runtime = "fixture-runtime"
	want, err := os.ReadFile(filepath.Join("..", "..", "contracts", "control-health", "v1", "fixture.json"))
	if err != nil {
		t.Fatalf("read canonical control-health fixture: %v", err)
	}

	// When
	got, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal canonical control health: %v", err)
	}

	// Then
	if !bytes.Equal(got, bytes.TrimSpace(want)) {
		t.Fatalf("security-engine fixture mismatch\ngot:  %s\nwant: %s", got, want)
	}
}

func TestSupervise_exhausts_restart_budget_on_production_path(t *testing.T) {
	// Given
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond})
	eng := New(config.Config{
		InputStreams:  []string{"telemetry:runtime"},
		ConsumerGroup: "supervision",
		ConsumerName:  "supervision-1",
		ReadBlock:     time.Millisecond,
		RestartBudget: 1,
	}, client)

	// When
	err := eng.Supervise(context.Background())

	// Then
	var supervisionErr *RuntimeSupervisionError
	if !errors.As(err, &supervisionErr) {
		t.Fatalf("supervision error = %T %v, want typed supervision failure", err, err)
	}
	health := eng.RuntimeHealth()
	if health.Reason != "restart_budget_exhausted" || health.PreventionEnabled || health.RestartCount != 1 {
		t.Fatalf("supervision did not fail closed: %+v", health)
	}
}

func TestSupervise_propagates_health_publication_failure_without_immediate_fail_closed(t *testing.T) {
	// Given
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond})
	eng := New(config.Config{
		InputStreams:        []string{"telemetry:runtime"},
		ConsumerGroup:       "publication-failure",
		ConsumerName:        "publication-failure-1",
		RestartBudget:       3,
		ControlHealthStream: "telemetry:runtime",
	}, client)

	// When
	err := eng.Supervise(context.Background())

	// Then
	var supervisionErr *RuntimeSupervisionError
	var publishErr *ControlHealthPublicationError
	if !errors.As(err, &supervisionErr) || !errors.As(err, &publishErr) {
		t.Fatalf("supervision error = %T %v, want typed publication failure", err, err)
	}
	health := eng.RuntimeHealth()
	if health.Reason != "restart_budget_exhausted" || health.PreventionEnabled || health.RestartCount != 3 {
		t.Fatalf("publication failure bypassed the restart policy: %+v", health)
	}
	if health.Publication.Status != controlHealthDegraded || health.Publication.RetryCount != 15 {
		t.Fatalf("publication failures were not retained in local health: %+v", health.Publication)
	}
}

func TestSnapshotContext_is_race_safe_on_production_path(t *testing.T) {
	// Given
	eng := New(config.Config{}, redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})

	// When
	go func() {
		defer close(done)
		for range 10 {
			eng.Activate(EmptyBundle(), LifecycleManifest{})
		}
	}()
	for range 10 {
		_, _ = eng.SnapshotContext(ctx)
	}
	<-done

	// Then
	if eng.RuntimeHealth().SchemaVersion != controlHealthSchemaVersion {
		t.Fatal("production snapshot path lost canonical runtime health")
	}
}
