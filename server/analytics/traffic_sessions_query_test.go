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

// P0-3: the read path must be able to page and filter a ClickHouse-backed
// session table, and must never issue an unbounded query.
func TestQueryTrafficSessionsBuildsFilteredPagedQuery(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queries = append(queries, string(body))
		if strings.HasPrefix(string(body), "SELECT count()") {
			_, _ = w.Write([]byte("137\n"))
			return
		}
		_, _ = w.Write([]byte(`{"session_uid":"eve-mirror0-http-1","observed_at":"2026-11-10 17:00:00.000000","agent_id":"local","sensor":"mirror0","src_ip":"10.1.18.252","dst_ip":"10.1.0.192","src_port":60268,"dst_port":80,"protocol":"TCP","app_proto":"http","vlan":39,"community_id":"1:abc=","flow_id":1668052616947290,"direction":"to_server","http_host":"cgzb.sru.edu.cn","http_method":"GET","http_uri":"/index.php","tls_sni":"","tls_ja3":"","tls_ja4":"","dns_query":""}` + "\n"))
	}))
	defer server.Close()
	client, err := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Database: "lyflow"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	from := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	page, err := client.QueryTrafficSessions(context.Background(), TrafficSessionQuery{
		Sensor:      "mirror0",
		SrcIP:       "10.1.18.252",
		AppProto:    "http",
		CommunityID: "1:abc=",
		FlowID:      "1668052616947290",
		From:        &from,
		Limit:       25,
		Offset:      50,
	})
	if err != nil {
		t.Fatalf("query sessions: %v", err)
	}

	// Then: totals and pagination come back to the caller.
	if page.Total != 137 {
		t.Fatalf("total=%d, want 137", page.Total)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items=%d, want 1", len(page.Items))
	}
	if page.Items[0]["http_host"] != "cgzb.sru.edu.cn" {
		t.Fatalf("L7 not promoted into the response: %#v", page.Items[0])
	}
	if page.Items[0]["community_id"] != "1:abc=" {
		t.Fatalf("join key missing from the response: %#v", page.Items[0])
	}

	// Every filter must reach ClickHouse, otherwise it silently returns more
	// rows than the operator asked for.
	selectSQL := queries[len(queries)-1]
	for _, fragment := range []string{
		"sensor = 'mirror0'",
		"app_proto = 'http'",
		"community_id = '1:abc='",
		"flow_id = 1668052616947290",
		"positionCaseInsensitive(src_ip, '10.1.18.252') > 0",
		"observed_at >= ",
		"ORDER BY observed_at DESC",
		"LIMIT 25",
		"OFFSET 50",
	} {
		if !strings.Contains(selectSQL, fragment) {
			t.Fatalf("query is missing %q:\n%s", fragment, selectSQL)
		}
	}
	// The list path must not pull raw_event: it averages 1.67 KiB per row and
	// measured 20.7s for 50 rows versus 1.3s without it.
	if strings.Contains(selectSQL, "raw_event") {
		t.Fatalf("list query must not select raw_event:\n%s", selectSQL)
	}
}

// ClickHouse quotes UInt64 as a JSON string by default. Declaring flow_id as a
// plain uint64 made every page fail to decode, and the handler silently fell
// back to Postgres — the feature looked deployed but never ran. This test pins
// both wire shapes.
func TestDecodeTrafficSessionRowsAcceptsQuotedAndRawUint64(t *testing.T) {
	quoted := `{"session_uid":"a","observed_at":"2026-11-10 17:00:00.000000","flow_id":"1668052616947290","vlan":39,"src_port":1234,"dst_port":80}`
	raw := `{"session_uid":"b","observed_at":"2026-11-10 17:00:00.000000","flow_id":1668052616947290,"vlan":39,"src_port":1,"dst_port":2}`

	items, err := decodeTrafficSessionRows([]byte(quoted + "\n" + raw + "\n"))
	if err != nil {
		t.Fatalf("decode rows: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items=%d, want 2", len(items))
	}
	if got := items[0]["flow_id"]; got != uint64(1668052616947290) {
		t.Fatalf("quoted flow_id decoded as %#v", got)
	}
	if got := items[1]["flow_id"]; got != uint64(1668052616947290) {
		t.Fatalf("raw flow_id decoded as %#v", got)
	}
}

// A null or empty flow_id must not fail the whole page.
func TestDecodeTrafficSessionRowsToleratesMissingFlowID(t *testing.T) {
	line := `{"session_uid":"c","observed_at":"2026-11-10 17:00:00.000000","flow_id":"","src_port":1,"dst_port":2}`
	items, err := decodeTrafficSessionRows([]byte(line + "\n"))
	if err != nil {
		t.Fatalf("decode rows: %v", err)
	}
	if len(items) != 1 || items[0]["flow_id"] != uint64(0) {
		t.Fatalf("items=%#v", items)
	}
}

// The per-session lookup is the one place that pays the raw_event cost, and it
// must address a single row by primary key.
func TestGetTrafficSessionSelectsRawEventForOneUID(t *testing.T) {
	var lastSelect string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lastSelect = string(body)
		_, _ = w.Write([]byte(`{"session_uid":"eve-mirror0-http-1","observed_at":"2026-11-10 17:00:00.000000","sensor":"mirror0","src_ip":"10.1.18.252","dst_ip":"10.1.0.192","protocol":"TCP","app_proto":"http","raw_event":"{}"}` + "\n"))
	}))
	defer server.Close()
	client, _ := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Database: "lyflow"})

	item, err := client.GetTrafficSession(context.Background(), "eve-mirror0-http-1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if item == nil || item["session_uid"] != "eve-mirror0-http-1" {
		t.Fatalf("unexpected item: %#v", item)
	}
	if !strings.Contains(lastSelect, "raw_event") {
		t.Fatalf("detail query must include raw_event:\n%s", lastSelect)
	}
	if !strings.Contains(lastSelect, "session_uid = 'eve-mirror0-http-1'") {
		t.Fatalf("detail query must filter by primary key:\n%s", lastSelect)
	}
}

// The row limit must be clamped so one request cannot pull the whole history
// through a 1 MB response body.
func TestQueryTrafficSessionsClampsLimit(t *testing.T) {
	var lastSelect string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(string(body), "SELECT count()") {
			_, _ = w.Write([]byte("5000\n"))
			return
		}
		lastSelect = string(body)
	}))
	defer server.Close()
	client, _ := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Database: "lyflow"})

	if _, err := client.QueryTrafficSessions(context.Background(), TrafficSessionQuery{Limit: 100000}); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !strings.Contains(lastSelect, "LIMIT 500") {
		t.Fatalf("limit was not clamped to 500:\n%s", lastSelect)
	}
}

// An empty filter set must still produce valid SQL rather than a dangling WHERE.
func TestQueryTrafficSessionsWithoutFilters(t *testing.T) {
	var lastSelect string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.HasPrefix(string(body), "SELECT count()") {
			_, _ = w.Write([]byte("0\n"))
			return
		}
		lastSelect = string(body)
	}))
	defer server.Close()
	client, _ := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Database: "lyflow"})

	if _, err := client.QueryTrafficSessions(context.Background(), TrafficSessionQuery{Limit: 10}); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !strings.Contains(lastSelect, "WHERE 1=1") {
		t.Fatalf("unfiltered query is malformed:\n%s", lastSelect)
	}
}

// Retention must be applied to a table that already exists, because the CREATE
// statement never runs again on an upgrade.
func TestEnsureTrafficSessionTTLModifiesExistingTable(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queries = append(queries, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, _ := NewHTTPClickHouse(HTTPClickHouseConfig{Endpoint: server.URL, Database: "lyflow"})

	if err := client.EnsureTrafficSessionTTL(context.Background()); err != nil {
		t.Fatalf("apply ttl: %v", err)
	}
	if len(queries) != 1 || !strings.Contains(queries[0], "MODIFY TTL") ||
		!strings.Contains(queries[0], "INTERVAL 30 DAY") {
		t.Fatalf("unexpected TTL statement: %#v", queries)
	}
}
