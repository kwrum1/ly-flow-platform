package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
	"github.com/redis/go-redis/v9"
)

func TestEventMigrationRuntimePhasesWithDisposableRedis(t *testing.T) {
	address := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("LYFLOW_TEST_REDIS_ADDR is required for the disposable Redis integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush task-owned Redis: %v", err)
	}

	runtime, err := NewEventMigrationRuntime(ctx, client, contracts.PhaseReaderFirst)
	if err != nil {
		t.Fatalf("create migration runtime: %v", err)
	}
	writeAlert := func(alert contracts.ComponentAlert) (string, error) {
		receipt, writeErr := runtime.WriteComponentAlert(ctx, alert, migrationRuntimeTestTime)
		return receipt.LegacyMessageID, writeErr
	}
	first := migrationTestAlert("alert-1")
	firstMessageID, err := writeAlert(first)
	if err != nil {
		t.Fatalf("reader-first write: %v", err)
	}
	assertStreamLengths(t, ctx, client, 1, 0)

	if err := runtime.Advance(ctx, contracts.PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	second := migrationTestAlert("alert-2")
	secondMessageID, err := writeAlert(second)
	if err != nil {
		t.Fatalf("dual write: %v", err)
	}
	replayedMessageID, err := writeAlert(second)
	if err != nil {
		t.Fatalf("replay dual write: %v", err)
	}
	if replayedMessageID != secondMessageID {
		t.Fatalf("replay changed deterministic message ID: first=%s replay=%s", secondMessageID, replayedMessageID)
	}
	assertStreamLengths(t, ctx, client, 2, 1)

	if err := runtime.Advance(ctx, contracts.PhaseReconcile); err != nil {
		t.Fatalf("advance reconcile: %v", err)
	}
	if replayedFirstID, err := writeAlert(first); err != nil || replayedFirstID != firstMessageID {
		t.Fatalf("reconcile replay: %v", err)
	}
	if eventUIDForAlert(first.ID) == "" || eventUIDForAlert(second.ID) == "" {
		t.Fatal("write receipt omitted deterministic event UID")
	}
	report, err := runtime.Reconcile(ctx)
	if err != nil || !report.Match {
		t.Fatalf("reconciliation mismatch: %+v (%v)", report, err)
	}
	assertStreamLengths(t, ctx, client, 2, 2)

	if err := runtime.Advance(ctx, contracts.PhaseReadSwitch); err != nil {
		t.Fatalf("advance read-switch: %v", err)
	}
	events, source, err := runtime.Read(ctx, 10)
	if err != nil || source != contracts.ReadCanonical || len(events) != 2 {
		t.Fatalf("canonical read failed: source=%s events=%d err=%v", source, len(events), err)
	}
	if err := runtime.Advance(ctx, contracts.PhaseObserve); err != nil {
		t.Fatalf("advance observe: %v", err)
	}
	observation := runtime.Observe()
	if observation.CanonicalReads != 2 || observation.LegacyReads != 0 || !observation.ReconciliationMatch {
		t.Fatalf("observe counters inaccurate: %+v", observation)
	}
	if err := runtime.Rollback(ctx); err != nil {
		t.Fatalf("rollback observe: %v", err)
	}
	_, source, err = runtime.Read(ctx, 10)
	if err != nil || source != contracts.ReadLegacy {
		t.Fatalf("rollback did not restore legacy reader: %s (%v)", source, err)
	}
	restored, err := NewEventMigrationRuntime(ctx, client, contracts.PhaseReaderFirst)
	if err != nil {
		t.Fatalf("restore persisted rollback state: %v", err)
	}
	if restored.Snapshot().Phase != contracts.PhaseReconcile {
		t.Fatalf("persisted rollback state not restored: %+v", restored.Snapshot())
	}
}

func TestEventMigrationRuntimeInterruptedWriteIsAtomicAndRetryable(t *testing.T) {
	runtime, client, ctx := disposableMigrationRuntime(t)
	if err := runtime.Advance(ctx, contracts.PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := runtime.WriteComponentAlert(cancelled, migrationTestAlert("interrupted"), migrationRuntimeTestTime); err == nil {
		t.Fatal("cancelled write unexpectedly succeeded")
	}
	assertStreamLengths(t, ctx, client, 0, 0)
	if _, err := runtime.WriteComponentAlert(ctx, migrationTestAlert("interrupted"), migrationRuntimeTestTime); err != nil {
		t.Fatalf("retry after interruption: %v", err)
	}
	assertStreamLengths(t, ctx, client, 1, 1)
}

func TestEventMigrationRetiresOnlyAfterPersistedFullHorizon(t *testing.T) {
	// Given
	runtime, client, ctx := disposableMigrationRuntime(t)
	for _, phase := range []contracts.MigrationPhase{contracts.PhaseDualWrite, contracts.PhaseReconcile, contracts.PhaseReadSwitch, contracts.PhaseObserve} {
		if err := runtime.Advance(ctx, phase); err != nil {
			t.Fatalf("advance %s: %v", phase, err)
		}
	}
	for _, producer := range transport.RequiredProducers() {
		if err := transport.RegisterProducer(ctx, client, producer); err != nil {
			t.Fatalf("register producer %s: %v", producer, err)
		}
	}
	store := transport.NewRedisHorizonStore(client)
	now := time.Now().UTC()
	if err := store.Persist(ctx, transport.HorizonRecord{MaximumSpoolRetryHorizon: 7 * 24 * time.Hour, ZeroLegacyReadsSince: now, AllProducersUpgraded: true, PersistedAt: now}); err != nil {
		t.Fatalf("persist early horizon: %v", err)
	}

	// When
	earlyErr := runtime.Retire(ctx, now.Add(30*time.Minute))
	if err := store.Persist(ctx, transport.HorizonRecord{MaximumSpoolRetryHorizon: 7 * 24 * time.Hour, ZeroLegacyReadsSince: now.Add(-7 * 24 * time.Hour), AllProducersUpgraded: true, PersistedAt: now}); err != nil {
		t.Fatalf("persist full horizon: %v", err)
	}
	fullErr := runtime.Retire(ctx, now)

	// Then
	if earlyErr == nil || fullErr != nil || runtime.Snapshot().Phase != contracts.PhaseRetireLegacy {
		t.Fatalf("retirement gate failed: early=%v full=%v snapshot=%+v", earlyErr, fullErr, runtime.Snapshot())
	}
}

func TestSecurityEventGovernanceHTTPAuthorizesRealSurfaces(t *testing.T) {
	runtime, _, ctx := disposableMigrationRuntime(t)
	if err := runtime.Advance(ctx, contracts.PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	if _, err := runtime.WriteComponentAlert(ctx, migrationTestAlert("governed"), migrationRuntimeTestTime); err != nil {
		t.Fatalf("seed governed event: %v", err)
	}
	if err := runtime.Advance(ctx, contracts.PhaseReconcile); err != nil {
		t.Fatalf("advance reconcile: %v", err)
	}
	if err := runtime.Advance(ctx, contracts.PhaseReadSwitch); err != nil {
		t.Fatalf("advance read-switch: %v", err)
	}
	handler := redisSecurityEventsHandler(runtime)

	assertGovernanceStatus(t, handler, http.MethodGet, "/api/v1/security-events", auth.RoleViewer, http.StatusForbidden)
	assertGovernanceStatus(t, handler, http.MethodGet, "/api/v1/security-events", auth.RoleAnalyst, http.StatusOK)
	assertGovernanceStatus(t, handler, http.MethodGet, "/api/v1/security-events/export", auth.RoleAnalyst, http.StatusForbidden)
	assertGovernanceStatus(t, handler, http.MethodGet, "/api/v1/security-events/export", auth.RoleAdmin, http.StatusOK)
	assertGovernanceStatus(t, handler, http.MethodDelete, "/api/v1/security-events/"+eventUIDForAlert("governed"), auth.RoleAnalyst, http.StatusForbidden)
	assertGovernanceStatus(t, handler, http.MethodDelete, "/api/v1/security-events/"+eventUIDForAlert("governed"), auth.RoleAdmin, http.StatusNoContent)
}

func TestEventMigrationCanonicalReaderQuarantinesFutureSchema(t *testing.T) {
	runtime, client, ctx := disposableMigrationRuntime(t)
	for _, phase := range []contracts.MigrationPhase{contracts.PhaseDualWrite, contracts.PhaseReconcile, contracts.PhaseReadSwitch} {
		if err := runtime.Advance(ctx, phase); err != nil {
			t.Fatalf("advance %s: %v", phase, err)
		}
	}
	if err := client.XAdd(ctx, &redis.XAddArgs{Stream: canonicalEventStream, Values: map[string]interface{}{
		"data": `{"schema_version":"lyflow.security_event.v99"}`,
	}}).Err(); err != nil {
		t.Fatalf("seed future event: %v", err)
	}
	_, _, err := runtime.Read(ctx, 10)
	var quarantine *contracts.QuarantineError
	if !errors.As(err, &quarantine) || quarantine.Reason != contracts.QuarantineFutureSchema {
		t.Fatalf("future schema was not quarantined: %v", err)
	}
}

func disposableMigrationRuntime(t *testing.T) (*EventMigrationRuntime, *redis.Client, context.Context) {
	t.Helper()
	address := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("LYFLOW_TEST_REDIS_ADDR is required for the disposable Redis integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	client := redis.NewClient(&redis.Options{Addr: address})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush task-owned Redis: %v", err)
	}
	runtime, err := NewEventMigrationRuntime(ctx, client, contracts.PhaseReaderFirst)
	if err != nil {
		t.Fatalf("create migration runtime: %v", err)
	}
	return runtime, client, ctx
}

var migrationRuntimeTestTime = time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

func migrationTestAlert(id string) contracts.ComponentAlert {
	return contracts.ComponentAlert{SchemaVersion: contracts.ComponentAlertSchemaVersion, ID: id, Category: contracts.TelemetryRuntime,
		SourceEngine: contracts.SourceEngineRuntime, RuleID: "rule-1", RuleName: "runtime rule", Severity: contracts.SeverityHigh,
		OccurredAt: migrationRuntimeTestTime.Add(-time.Minute), Source: "runtime", Entities: contracts.EntityRef{AgentID: "agent-1"},
		Summary: "runtime alert", Details: map[string]interface{}{"nested": []interface{}{map[string]interface{}{"token": "secret"}}}}
}

func eventUIDForAlert(id string) string {
	return contracts.DeterministicEventUID(contracts.SourceAgentRuntime, "agent-1", id)
}

func assertStreamLengths(t *testing.T, ctx context.Context, client *redis.Client, legacy, canonical int64) {
	t.Helper()
	legacyCount, err := client.XLen(ctx, legacyComponentAlertStream).Result()
	if err != nil {
		t.Fatalf("read legacy length: %v", err)
	}
	canonicalCount, err := client.XLen(ctx, canonicalEventStream).Result()
	if err != nil {
		t.Fatalf("read canonical length: %v", err)
	}
	if legacyCount != legacy || canonicalCount != canonical {
		t.Fatalf("stream lengths legacy=%d canonical=%d, want %d/%d", legacyCount, canonicalCount, legacy, canonical)
	}
}

func assertGovernanceStatus(t *testing.T, handler http.Handler, method, path string, role auth.UserRole, expected int) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(""))
	request = request.WithContext(context.WithValue(request.Context(), auth.RoleContextKey, role))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != expected {
		var body map[string]interface{}
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		t.Fatalf("%s %s as %s returned %d (%v), want %d", method, path, role, response.Code, body, expected)
	}
}
