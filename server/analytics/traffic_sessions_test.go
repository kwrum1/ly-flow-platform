package analytics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPClickHouseTrafficSessions_ensures_schema_and_inserts_full_record(t *testing.T) {
	queries := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queries = append(queries, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Database: "lyflow"})
	if err != nil {
		t.Fatalf("create ClickHouse client: %v", err)
	}
	ctx := context.Background()
	if err := client.EnsureTrafficSessionTable(ctx); err != nil {
		t.Fatalf("ensure session table: %v", err)
	}
	if err := client.InsertTrafficSession(ctx, TrafficSessionRecord{
		SessionUID: "session-1", Version: 2, ObservedAt: time.Date(2026, 7, 30, 12, 0, 0, 123000, time.UTC),
		AgentID: "agent-1", SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: 12345, DstPort: 443,
		Protocol: "tcp", RawEvent: `{"complete":true}`, IngestedAt: time.Date(2026, 7, 30, 12, 0, 1, 0, time.UTC),
	}); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "ReplacingMergeTree(version)") ||
		!strings.Contains(queries[1], "INSERT INTO lyflow_traffic_sessions FORMAT JSONEachRow") ||
		!strings.Contains(queries[1], `"session_uid":"session-1"`) ||
		!strings.Contains(queries[1], `"raw_event":"{\"complete\":true}"`) {
		t.Fatalf("unexpected ClickHouse queries: %#v", queries)
	}
}

func TestTrafficSessionTableDDL_preserves_full_session_and_trace_dimensions(t *testing.T) {
	for _, column := range []string{"session_uid", "observed_at", "agent_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "raw_event"} {
		if !strings.Contains(TrafficSessionTableDDL, column) {
			t.Fatalf("session DDL missing %s", column)
		}
	}
	if !strings.Contains(TrafficSessionTableDDL, "ORDER BY (session_uid)") {
		t.Fatal("session UID must be the replacement key for idempotent retries")
	}
	if strings.Contains(strings.ToUpper(TrafficSessionTableDDL), " TTL ") {
		t.Fatal("full-session history must not expire without an explicit retention policy")
	}
}
