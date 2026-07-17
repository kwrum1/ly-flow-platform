package analytics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClickHouse_hung_request_times_out_as_backpressure(t *testing.T) {
	// Given
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When
	err = client.Insert(context.Background(), testStorageEvent("hung", 1))
	close(release)

	// Then
	if !errors.Is(err, ErrStorageBackpressure) {
		t.Fatalf("error=%v, want backpressure", err)
	}
}

func TestHTTPClickHouse_misleading_success_body_fails_query(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("not-json"))
	}))
	t.Cleanup(server.Close)
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When
	_, err = client.QueryFinal(context.Background(), 10)

	// Then
	if err == nil {
		t.Fatal("misleading HTTP success was accepted as a valid query result")
	}
}

func TestEventStorageMigration_stale_owner_and_rollback_window_fail_closed(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	otherOwner, err := NewStorageMigration(StorageMigrationConfig{
		Postgres: manager.postgres, ClickHouse: manager.clickhouse, Owner: "stale-owner",
		RollbackWindow: time.Hour,
	})
	if err != nil {
		t.Fatalf("create stale owner: %v", err)
	}

	// When
	ownerErr := otherOwner.Advance(ctx, PhaseDualWrite)
	_, updateErr := manager.postgres.Exec(ctx, `UPDATE lyflow_event_storage_control SET
		phase=$1, rollback_until=NOW()-INTERVAL '1 second' WHERE singleton=TRUE`, PhaseRetireLegacy)
	if updateErr != nil {
		t.Fatalf("seed expired rollback window: %v", updateErr)
	}
	rollbackErr := manager.Rollback(ctx)

	// Then
	if ownerErr == nil || !errors.Is(rollbackErr, ErrInvalidTransition) {
		t.Fatalf("ownerErr=%v rollbackErr=%v", ownerErr, rollbackErr)
	}
}

func TestEventStorageMigration_repeated_migration_preserves_dirty_store(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := manager.Write(ctx, testStorageEvent("dirty-store", 1)); err != nil {
		t.Fatalf("seed existing store: %v", err)
	}

	// When
	err := manager.Migrate(ctx)
	result, searchErr := manager.Search(ctx, 10)

	// Then
	if err != nil || searchErr != nil || len(result.Events) != 1 || result.Events[0].ID != "dirty-store" {
		t.Fatalf("migrate=%v search=%v result=%+v", err, searchErr, result)
	}
}

func TestEventStorageMigration_interrupted_clickhouse_write_remains_pending(t *testing.T) {
	// Given
	manager, ctx := realStorageMigration(t)
	if err := manager.Advance(ctx, PhaseDualWrite); err != nil {
		t.Fatalf("advance dual-write: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatalf("create interruptible client: %v", err)
	}
	interrupted := manager.WithClickHouse(client)
	writeContext, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		result <- interrupted.Write(writeContext, testStorageEvent("interrupted", 1))
	}()

	// When
	<-started
	cancel()
	writeErr := <-result
	close(release)
	status, statusErr := manager.Status(ctx)

	// Then
	if statusErr != nil || !errors.Is(writeErr, ErrStorageBackpressure) || status.PendingWrites != 1 || !status.Degraded {
		t.Fatalf("write=%v status=%+v statusErr=%v", writeErr, status, statusErr)
	}
	if _, err := manager.Backfill(ctx, 10); err != nil {
		t.Fatalf("recover interrupted write: %v", err)
	}
}
