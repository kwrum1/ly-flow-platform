package analytics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStoragePhasePolicy_routes_authoritative_sources(t *testing.T) {
	// Given
	tests := []struct {
		phase StoragePhase
		read  ReadAuthority
		write WriteAuthority
	}{
		{PhaseLegacy, ReadPostgres, WritePostgres},
		{PhaseDualWrite, ReadPostgres, WritePostgresAndClickHouse},
		{PhaseReconcile, ReadReconciled, WritePostgresAndClickHouse},
		{PhaseReadSwitch, ReadClickHouse, WritePostgresAndClickHouse},
		{PhaseObserve, ReadClickHouse, WritePostgresAndClickHouse},
		{PhaseRetireLegacy, ReadClickHouse, WritePostgresAndClickHouse},
	}

	for _, test := range tests {
		t.Run(string(test.phase), func(t *testing.T) {
			// When
			policy, err := PolicyForPhase(test.phase)

			// Then
			if err != nil || policy.Read != test.read || policy.Write != test.write {
				t.Fatalf("policy=%+v err=%v, want read=%s write=%s", policy, err, test.read, test.write)
			}
			if policy.Control != ControlPostgres {
				t.Fatalf("control authority=%s, want %s", policy.Control, ControlPostgres)
			}
		})
	}
}

func TestStoragePhasePolicy_rejects_unknown_phase(t *testing.T) {
	// When
	_, err := PolicyForPhase(StoragePhase("future"))

	// Then
	if !errors.Is(err, ErrInvalidStoragePhase) {
		t.Fatalf("error=%v, want ErrInvalidStoragePhase", err)
	}
}

func TestClickHouseSchema_uses_versioned_uid_finalization_without_retention_claim(t *testing.T) {
	// When
	ddl := ClickHouseEventMigrationDDL

	// Then
	for _, required := range []string{"ReplacingMergeTree(version)", "ORDER BY (event_uid)", "FINAL"} {
		if !strings.Contains(ddl, required) {
			t.Fatalf("schema contract missing %q: %s", required, ddl)
		}
	}
	for _, forbidden := range []string{"TTL ", "DELETE WHERE", "retention_enabled"} {
		if strings.Contains(ddl, forbidden) {
			t.Fatalf("unmeasured retention claim %q is enabled: %s", forbidden, ddl)
		}
	}
}

func TestHTTPClickHouse_disk_full_is_typed_backpressure(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInsufficientStorage)
		_, _ = writer.Write([]byte("Code: 243. DB::Exception: Cannot write: No space left on device"))
	}))
	t.Cleanup(server.Close)
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// When
	err = client.Insert(context.Background(), testStorageEvent("disk-full", 1))

	// Then
	if !errors.Is(err, ErrStorageBackpressure) || !errors.Is(err, ErrClickHouseDiskFull) {
		t.Fatalf("error=%v, want disk-full backpressure", err)
	}
}

func TestRetentionPolicy_stays_disabled_without_measurement(t *testing.T) {
	// Given
	policy := DefaultRetentionPolicy()

	// When
	err := policy.AuthorizeExpiry(time.Now().UTC())

	// Then
	if policy.ClaimsEnabled || !errors.Is(err, ErrRetentionUnmeasured) {
		t.Fatalf("policy=%+v err=%v, want disabled retention", policy, err)
	}
}

func TestEventChecksum_is_stable_across_storage_timezones(t *testing.T) {
	// Given
	utc := testStorageEvent("timezone", 1)
	local := utc
	local.Timestamp = utc.Timestamp.In(time.FixedZone("CST", 8*60*60))

	// When
	utcChecksum := checksumEvents([]EventRecord{utc})
	localChecksum := checksumEvents([]EventRecord{local})

	// Then
	if utcChecksum != localChecksum {
		t.Fatalf("checksums differ for the same instant: utc=%s local=%s", utcChecksum, localChecksum)
	}
}

func testStorageEvent(uid string, version uint64) EventRecord {
	return EventRecord{
		ID: uid, Version: version, Timestamp: time.Date(2026, 7, 14, 12, 0, int(version), 0, time.UTC),
		SourceModule: "security", EventType: "alert", Severity: "high", AgentID: "agent-1",
		HostID: "host-1", Message: "event-" + uid, PayloadJSON: `{"uid":"` + uid + `"}`,
	}
}
