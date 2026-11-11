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
		AgentID: "agent-1", Sensor: "mirror0",
		SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: 12345, DstPort: 443,
		Protocol: "tcp",
		// P0-4 join keys and P0-5 L7 facts must survive into the INSERT.
		AppProto: "tls", VLAN: 39,
		CommunityID: "1:abc=", FlowID: 741611833741618, Direction: "to_server",
		HTTPHost: "portal.example.test", HTTPMethod: "GET", HTTPURI: "/a",
		TLSSNI: "portal.example.test", TLSJA3: "ja3hash", TLSJA4: "ja4hash",
		DNSQuery: "q.example.test",
		RawEvent: `{"complete":true}`, IngestedAt: time.Date(2026, 7, 30, 12, 0, 1, 0, time.UTC),
	}); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	// One CREATE, one ALTER per column added to a pre-existing deployment, one
	// MODIFY TTL, then the INSERT.
	wantAlters := len(trafficSessionColumns)
	wantQueries := wantAlters + 3
	if len(queries) != wantQueries {
		t.Fatalf("query count=%d, want %d (1 create + %d alters + 1 ttl + 1 insert)", len(queries), wantQueries, wantAlters)
	}
	if !strings.Contains(queries[0], "ReplacingMergeTree(version)") {
		t.Fatalf("first query is not the table DDL: %s", queries[0])
	}
	for index := 1; index <= wantAlters; index++ {
		if !strings.Contains(queries[index], "ADD COLUMN IF NOT EXISTS") {
			t.Fatalf("query %d is not an idempotent ALTER: %s", index, queries[index])
		}
	}
	if !strings.Contains(queries[wantAlters+1], "MODIFY TTL") {
		t.Fatalf("retention was not applied to the existing table: %s", queries[wantAlters+1])
	}
	insert := queries[len(queries)-1]
	for _, fragment := range []string{
		"INSERT INTO lyflow_traffic_sessions FORMAT JSONEachRow",
		`"session_uid":"session-1"`,
		`"raw_event":"{\"complete\":true}"`,
		`"community_id":"1:abc="`,
		`"flow_id":741611833741618`,
		`"sensor":"mirror0"`,
		`"vlan":39`,
		`"app_proto":"tls"`,
		`"http_host":"portal.example.test"`,
		`"tls_sni":"portal.example.test"`,
		`"tls_ja3":"ja3hash"`,
		`"tls_ja4":"ja4hash"`,
		`"dns_query":"q.example.test"`,
	} {
		if !strings.Contains(insert, fragment) {
			t.Fatalf("insert is missing %s: %s", fragment, insert)
		}
	}
}

func TestTrafficSessionTableDDL_preserves_full_session_and_trace_dimensions(t *testing.T) {
	for _, column := range []string{"session_uid", "observed_at", "agent_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "raw_event"} {
		if !strings.Contains(TrafficSessionTableDDL, column) {
			t.Fatalf("session DDL missing %s", column)
		}
	}
	// P0-4 join keys and P0-5 L7 facts are first-class columns, not raw_event
	// only, so alert->session correlation does not require JSON parsing.
	for _, column := range []string{
		"sensor", "app_proto", "vlan", "community_id", "flow_id", "direction",
		"http_host", "http_method", "http_uri",
		"tls_sni", "tls_ja3", "tls_ja4", "dns_query",
	} {
		if !strings.Contains(TrafficSessionTableDDL, column) {
			t.Fatalf("session DDL missing correlation column %s", column)
		}
	}
	if !strings.Contains(TrafficSessionTableDDL, "ORDER BY (session_uid)") {
		t.Fatal("session UID must be the replacement key for idempotent retries")
	}
	// P0-3: the table must carry an explicit retention TTL. Without one the
	// history grows without bound, which is exactly the failure mode the
	// Postgres store had (15 GB for three days of data).
	if !strings.Contains(TrafficSessionTableDDL, "TTL") {
		t.Fatal("full-session history must declare a retention TTL")
	}
	if !strings.Contains(TrafficSessionTableDDL, "INTERVAL 30 DAY") {
		t.Fatalf("unexpected retention expression in DDL:\n%s", TrafficSessionTableDDL)
	}
}

// A deployment that already has the pre-P0 table must upgrade in place: every
// new column is added with IF NOT EXISTS so a restart is idempotent and no rows
// are lost.
func TestTrafficSessionTableUpgradeIsAdditive(t *testing.T) {
	if len(trafficSessionColumns) == 0 {
		t.Fatal("no incremental columns declared")
	}
	for _, column := range trafficSessionColumns {
		if column.Name == "" || column.Type == "" {
			t.Fatalf("malformed column spec: %+v", column)
		}
		if !strings.Contains(TrafficSessionTableDDL, column.Name+" ") {
			t.Fatalf("fresh DDL and the upgrade list disagree on %s", column.Name)
		}
	}
}
