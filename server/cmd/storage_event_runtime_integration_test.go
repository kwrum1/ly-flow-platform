package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func TestNormalizeStoredCanonicalPayload_repairs_legacy_governance_metadata(t *testing.T) {
	event := canonicalXDRTestEvent(t, "legacy-secret", time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC))
	event.Payload = json.RawMessage(`{"token":"legacy-value","command":"whoami"}`)
	event.Governance.RedactedFields = nil
	stored, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode legacy event: %v", err)
	}

	normalized, err := normalizeStoredCanonicalPayload(event.EventUID, string(stored))
	if err != nil {
		t.Fatalf("normalize legacy event: %v", err)
	}
	var repaired contracts.CanonicalSecurityEvent
	if err := json.Unmarshal(normalized, &repaired); err != nil {
		t.Fatalf("decode repaired event: %v", err)
	}
	if err := repaired.Validate(); err != nil {
		t.Fatalf("repaired event invalid: %v", err)
	}
	if string(repaired.Payload) != `{"command":"whoami","token":"***REDACTED***"}` {
		t.Fatalf("payload=%s", repaired.Payload)
	}
	if len(repaired.Governance.RedactedFields) != 1 || repaired.Governance.RedactedFields[0] != "token" {
		t.Fatalf("redacted fields=%v", repaired.Governance.RedactedFields)
	}
}

func TestProductionStorageRuntime_uses_clickhouse_settings_and_real_security_event_routes(t *testing.T) {
	// Given
	endpoint := os.Getenv("LYFLOW_TEST_CLICKHOUSE_HTTP")
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if endpoint == "" || dsn == "" {
		t.Skip("real ClickHouse and Postgres stores are required")
	}
	t.Setenv("CLICKHOUSE_ADDR", endpoint)
	t.Setenv("CLICKHOUSE_DB", "default")
	t.Setenv("CLICKHOUSE_USER", os.Getenv("LYFLOW_TEST_CLICKHOUSE_USER"))
	t.Setenv("CLICKHOUSE_PASSWORD", os.Getenv("LYFLOW_TEST_CLICKHOUSE_PASSWORD"))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect Postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	fixture := storageRuntimeTestFixture{
		postgres:           pool,
		clickHouseAddress:  endpoint,
		clickHouseUsername: os.Getenv("LYFLOW_TEST_CLICKHOUSE_USER"),
		clickHousePassword: os.Getenv("LYFLOW_TEST_CLICKHOUSE_PASSWORD"),
	}
	if err := resetStorageRuntimeTestState(ctx, fixture); err != nil {
		t.Fatalf("reset storage runtime state: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if err := resetStorageRuntimeTestState(cleanupCtx, fixture); err != nil {
			t.Fatalf("cleanup storage runtime state: %v", err)
		}
	})
	runtime, err := newProductionStorageEventRuntime(ctx, pool)
	if err != nil {
		t.Fatalf("initialize production storage runtime: %v", err)
	}
	alert := migrationTestAlert("storage-route")
	event, err := alert.Canonical(contracts.PrincipalIdentity(alert.Entities.AgentID), migrationRuntimeTestTime)
	if err != nil {
		t.Fatalf("canonical event: %v", err)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("encode event: %v", err)
	}
	events := securityEventsHandler(runtime)
	phases := storageMigrationHandler(runtime)

	// When
	post := httptest.NewRequest(http.MethodPost, "/api/v1/security-events", bytes.NewReader(payload))
	post = post.WithContext(context.WithValue(post.Context(), auth.RoleContextKey, auth.RoleAnalyst))
	postResponse := httptest.NewRecorder()
	events.ServeHTTP(postResponse, post)
	for _, control := range []string{
		`{"action":"advance","phase":"dual_write"}`,
		`{"action":"backfill"}`,
		`{"action":"advance","phase":"reconcile"}`,
		`{"action":"reconcile"}`,
		`{"action":"advance","phase":"read_switch"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/event-migration", bytes.NewBufferString(control))
		response := httptest.NewRecorder()
		phases.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("phase control %s returned %d: %s", control, response.Code, response.Body.String())
		}
	}
	get := httptest.NewRequest(http.MethodGet, "/api/v1/security-events?limit=10", nil)
	get = get.WithContext(context.WithValue(get.Context(), auth.RoleContextKey, auth.RoleAnalyst))
	getResponse := httptest.NewRecorder()
	events.ServeHTTP(getResponse, get)

	// Then
	if postResponse.Code != http.StatusCreated || getResponse.Code != http.StatusOK {
		t.Fatalf("post=%d %s get=%d %s", postResponse.Code, postResponse.Body.String(), getResponse.Code, getResponse.Body.String())
	}
	var result struct {
		ReadSource string                             `json:"read_source"`
		Events     []contracts.CanonicalSecurityEvent `json:"events"`
	}
	if err := json.Unmarshal(getResponse.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ReadSource != "clickhouse" || len(result.Events) != 1 || result.Events[0].EventUID != event.EventUID {
		t.Fatalf("result=%+v", result)
	}
}

type storageRuntimeTestFixture struct {
	postgres           *pgxpool.Pool
	clickHouseAddress  string
	clickHouseUsername string
	clickHousePassword string
}

func resetStorageRuntimeTestState(ctx context.Context, fixture storageRuntimeTestFixture) error {
	for _, query := range []string{
		"DROP TABLE IF EXISTS lyflow_security_events_versioned_transition",
		"DROP TABLE IF EXISTS lyflow_security_events_pre_versioned",
		"DROP TABLE IF EXISTS lyflow_security_events",
		"DROP TABLE IF EXISTS lyflow_event_storage_migrations",
	} {
		if err := clickHouseRuntimeTestQuery(ctx, fixture, query); err != nil {
			return err
		}
	}
	if _, err := fixture.postgres.Exec(ctx, `DROP TABLE IF EXISTS lyflow_event_storage_outbox;
DROP TABLE IF EXISTS lyflow_event_storage_control;
DROP TABLE IF EXISTS lyflow_event_storage_events;
DROP TABLE IF EXISTS lyflow_event_storage_migrations`); err != nil {
		return err
	}
	return nil
}

func clickHouseRuntimeTestQuery(ctx context.Context, fixture storageRuntimeTestFixture, query string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fixture.clickHouseAddress, strings.NewReader(query))
	if err != nil {
		return fmt.Errorf("create ClickHouse request: %w", err)
	}
	if fixture.clickHouseUsername != "" {
		request.SetBasicAuth(fixture.clickHouseUsername, fixture.clickHousePassword)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("query ClickHouse: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			return fmt.Errorf("read ClickHouse response: %w", readErr)
		}
		return fmt.Errorf("ClickHouse status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
