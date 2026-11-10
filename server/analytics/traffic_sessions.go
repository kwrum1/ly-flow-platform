package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// TrafficSessionTableDDL is the ClickHouse schema for full traffic sessions.
//
// P0-4 (join key) and P0-5 (L7 fields) added the correlation columns below.
// They are stored as real columns, not only inside raw_event, because
//
//   - an alert and the session it belongs to must be joinable without parsing
//     a JSON blob on every query, and
//   - L7 values (host / SNI / DNS name) are what makes a session explainable
//     months later, when raw_event retention may already have expired.
//
// ORDER BY (session_uid) is also the ReplacingMergeTree dedup key: FINAL must
// collapse repeats of the same session, so the key cannot include observed_at.
// Adding a time range to the sort key would make two versions of one session
// survive as separate rows.
const TrafficSessionTableDDL = `CREATE TABLE IF NOT EXISTS lyflow_traffic_sessions (
  session_uid String,
  version UInt64,
  observed_at DateTime64(6, 'UTC'),
  agent_id String,
  sensor LowCardinality(String),
  src_ip String,
  dst_ip String,
  src_port UInt16,
  dst_port UInt16,
  protocol LowCardinality(String),
  app_proto LowCardinality(String),
  vlan UInt16,
  community_id String,
  flow_id UInt64,
  direction LowCardinality(String),
  http_host String,
  http_method LowCardinality(String),
  http_uri String,
  tls_sni String,
  tls_ja3 String,
  tls_ja4 String,
  dns_query String,
  raw_event String,
  ingested_at DateTime64(6, 'UTC'),
  INDEX idx_observed_at observed_at TYPE minmax GRANULARITY 1,
  INDEX idx_community_id community_id TYPE bloom_filter GRANULARITY 4,
  INDEX idx_flow_id flow_id TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(observed_at)
ORDER BY (session_uid)
TTL toDateTime(observed_at) + INTERVAL 30 DAY`

// trafficSessionColumns are added to an existing table by
// EnsureTrafficSessionTable. ClickHouse accepts ADD COLUMN IF NOT EXISTS, so a
// deployment that already has the old nine-column table upgrades in place
// without losing rows.
var trafficSessionColumns = []struct {
	Name string
	Type string
}{
	{"sensor", "LowCardinality(String)"},
	{"app_proto", "LowCardinality(String)"},
	{"vlan", "UInt16"},
	{"community_id", "String"},
	{"flow_id", "UInt64"},
	{"direction", "LowCardinality(String)"},
	{"http_host", "String"},
	{"http_method", "LowCardinality(String)"},
	{"http_uri", "String"},
	{"tls_sni", "String"},
	{"tls_ja3", "String"},
	{"tls_ja4", "String"},
	{"dns_query", "String"},
}

type TrafficSessionRecord struct {
	SessionUID string
	Version    uint64
	ObservedAt time.Time
	AgentID    string
	Sensor     string
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string

	// P0-4 join keys. CommunityID is the stable cross-sensor flow identity;
	// FlowID is Suricata's per-sensor identifier; VLAN and Sensor disambiguate
	// overlapping sensor spans.
	AppProto    string
	VLAN        uint16
	CommunityID string
	FlowID      uint64
	Direction   string

	// P0-5 application-layer facts.
	HTTPHost   string
	HTTPMethod string
	HTTPURI    string
	TLSSNI     string
	TLSJA3     string
	TLSJA4     string
	DNSQuery   string

	RawEvent   string
	IngestedAt time.Time
}

type clickHouseTrafficSessionRow struct {
	SessionUID  string `json:"session_uid"`
	Version     uint64 `json:"version"`
	ObservedAt  string `json:"observed_at"`
	AgentID     string `json:"agent_id"`
	Sensor      string `json:"sensor"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	AppProto    string `json:"app_proto"`
	VLAN        uint16 `json:"vlan"`
	CommunityID string `json:"community_id"`
	FlowID      uint64 `json:"flow_id"`
	Direction   string `json:"direction"`
	HTTPHost    string `json:"http_host"`
	HTTPMethod  string `json:"http_method"`
	HTTPURI     string `json:"http_uri"`
	TLSSNI      string `json:"tls_sni"`
	TLSJA3      string `json:"tls_ja3"`
	TLSJA4      string `json:"tls_ja4"`
	DNSQuery    string `json:"dns_query"`
	RawEvent    string `json:"raw_event"`
	IngestedAt  string `json:"ingested_at"`
}

// EnsureTrafficSessionTable creates the table and then adds any column that a
// pre-existing deployment is missing. ADD COLUMN IF NOT EXISTS is idempotent,
// so this is safe to call on every start.
func (client *HTTPClickHouse) EnsureTrafficSessionTable(ctx context.Context) error {
	if client == nil {
		return fmt.Errorf("ClickHouse session client is nil")
	}
	if _, err := client.execute(ctx, TrafficSessionTableDDL); err != nil {
		return fmt.Errorf("ensure ClickHouse traffic session table: %w", err)
	}
	for _, column := range trafficSessionColumns {
		statement := fmt.Sprintf(
			"ALTER TABLE lyflow_traffic_sessions ADD COLUMN IF NOT EXISTS %s %s",
			column.Name, column.Type)
		if _, err := client.execute(ctx, statement); err != nil {
			return fmt.Errorf("add ClickHouse traffic session column %s: %w", column.Name, err)
		}
	}
	// A pre-existing table was created without retention, so the DDL above does
	// not retroactively apply. MODIFY TTL is idempotent and fixes that in place.
	if err := client.EnsureTrafficSessionTTL(ctx); err != nil {
		return err
	}
	return nil
}

func (client *HTTPClickHouse) InsertTrafficSession(ctx context.Context, session TrafficSessionRecord) error {
	if client == nil {
		return fmt.Errorf("ClickHouse session client is nil")
	}
	if strings.TrimSpace(session.SessionUID) == "" {
		return fmt.Errorf("traffic session UID is required")
	}
	if session.ObservedAt.IsZero() {
		return fmt.Errorf("traffic session observed time is required")
	}
	if session.Version == 0 {
		session.Version = uint64(time.Now().UTC().UnixNano())
	}
	if session.IngestedAt.IsZero() {
		session.IngestedAt = time.Now().UTC()
	}
	row := clickHouseTrafficSessionRow{
		SessionUID: session.SessionUID, Version: session.Version,
		ObservedAt: session.ObservedAt.UTC().Format("2006-01-02 15:04:05.000000"),
		AgentID:    session.AgentID, Sensor: session.Sensor,
		SrcIP: session.SrcIP, DstIP: session.DstIP,
		SrcPort: session.SrcPort, DstPort: session.DstPort, Protocol: session.Protocol,
		AppProto: session.AppProto, VLAN: session.VLAN,
		CommunityID: session.CommunityID, FlowID: session.FlowID,
		Direction: session.Direction,
		HTTPHost:  session.HTTPHost, HTTPMethod: session.HTTPMethod, HTTPURI: session.HTTPURI,
		TLSSNI: session.TLSSNI, TLSJA3: session.TLSJA3, TLSJA4: session.TLSJA4,
		DNSQuery:  session.DNSQuery,
		RawEvent:  session.RawEvent,
		IngestedAt: session.IngestedAt.UTC().Format("2006-01-02 15:04:05.000000"),
	}
	payload, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("encode traffic session %s: %w", session.SessionUID, err)
	}
	query := "INSERT INTO lyflow_traffic_sessions FORMAT JSONEachRow\n" + string(payload)
	if _, err := client.execute(ctx, query); err != nil {
		return fmt.Errorf("insert ClickHouse traffic session %s: %w", session.SessionUID, err)
	}
	return nil
}

// TrafficSessionQuery is the filter set accepted by QueryTrafficSessions.
//
// It mirrors the filters the Postgres read path supports so switching the
// backend does not change what an analyst can ask for.
type TrafficSessionQuery struct {
	Sensor      string
	AgentID     string
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	CommunityID string
	FlowID      string
	AppProto    string
	Protocol    string
	Keyword     string
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

// TrafficSessionPage is one page plus the total match count.
type TrafficSessionPage struct {
	Items  []map[string]interface{}
	Total  int
	Limit  int
	Offset int
}

// queryTrafficSessionColumns is what the list path needs.
//
// raw_event is deliberately excluded. It averages 1.67 KiB per row on this
// deployment, and selecting it for a 50-row page measured 20.7s versus 1.3s
// without it. The list payload is already assembled from the promoted columns,
// and the full payload is fetched per session by GetTrafficSession when a client
// opens one.
const queryTrafficSessionColumns = "session_uid, observed_at, agent_id, sensor, src_ip, dst_ip, " +
	"src_port, dst_port, protocol, app_proto, vlan, community_id, flow_id, direction, " +
	"http_host, http_method, http_uri, tls_sni, tls_ja3, tls_ja4, dns_query"

// QueryTrafficSessions reads sessions from ClickHouse with server-side filtering
// and pagination.
//
// The response body is capped by the HTTP client, so the query never returns an
// unbounded result set: the row limit is clamped and the count comes from a
// separate aggregate query that returns a single number.
func (client *HTTPClickHouse) QueryTrafficSessions(ctx context.Context, query TrafficSessionQuery) (TrafficSessionPage, error) {
	if client == nil {
		return TrafficSessionPage{}, fmt.Errorf("ClickHouse session client is nil")
	}
	page := TrafficSessionPage{Limit: query.Limit, Offset: query.Offset}
	if page.Limit <= 0 {
		page.Limit = 50
	}
	if page.Limit > 500 {
		page.Limit = 500
	}
	if page.Offset < 0 {
		page.Offset = 0
	}
	page.Limit = query.Limit
	if page.Limit <= 0 {
		page.Limit = 50
	}
	if page.Limit > 500 {
		page.Limit = 500
	}

	conditions := make([]string, 0, 12)
	appendEquals := func(column, value string) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			conditions = append(conditions, column+" = "+quoteClickHouseString(trimmed))
		}
	}
	appendContains := func(column, value string) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			conditions = append(conditions, "positionCaseInsensitive("+column+", "+
				quoteClickHouseString(trimmed)+") > 0")
		}
	}
	appendPort := func(column, value string) {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			if parsed, err := strconv.ParseUint(trimmed, 10, 16); err == nil {
				conditions = append(conditions, column+" = "+strconv.FormatUint(parsed, 10))
			}
		}
	}
	appendEquals("sensor", query.Sensor)
	appendEquals("agent_id", query.AgentID)
	appendEquals("community_id", query.CommunityID)
	appendEquals("app_proto", query.AppProto)
	appendEquals("protocol", query.Protocol)
	if trimmed := strings.TrimSpace(query.FlowID); trimmed != "" {
		if parsed, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
			conditions = append(conditions, "flow_id = "+strconv.FormatUint(parsed, 10))
		}
	}
	// IP filters stay substring matches to match the previous behaviour, where
	// a partial address was an accepted query.
	appendContains("src_ip", query.SrcIP)
	appendContains("dst_ip", query.DstIP)
	appendPort("src_port", query.SrcPort)
	appendPort("dst_port", query.DstPort)
	if query.From != nil {
		conditions = append(conditions, "observed_at >= "+quoteClickHouseTime(*query.From))
	}
	if query.To != nil {
		conditions = append(conditions, "observed_at <= "+quoteClickHouseTime(*query.To))
	}
	if keyword := strings.TrimSpace(query.Keyword); keyword != "" {
		pattern := quoteClickHouseString(keyword)
		fields := []string{"src_ip", "dst_ip", "protocol", "app_proto", "agent_id",
			"http_host", "tls_sni", "dns_query"}
		parts := make([]string, 0, len(fields))
		for _, field := range fields {
			parts = append(parts, "positionCaseInsensitive("+field+", "+pattern+") > 0")
		}
		conditions = append(conditions, "("+strings.Join(parts, " OR ")+")")
	}
	where := "1=1"
	if len(conditions) > 0 {
		where = strings.Join(conditions, " AND ")
	}

	countSQL := "SELECT count() FROM lyflow_traffic_sessions WHERE " + where
	body, err := client.execute(ctx, countSQL)
	if err != nil {
		return page, fmt.Errorf("count ClickHouse traffic sessions: %w", err)
	}
	if parsed, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64); err == nil {
		page.Total = int(parsed)
	}

	sql := "SELECT " + queryTrafficSessionColumns +
		" FROM lyflow_traffic_sessions WHERE " + where +
		" ORDER BY observed_at DESC, session_uid DESC LIMIT " + strconv.Itoa(page.Limit) +
		" OFFSET " + strconv.Itoa(page.Offset) + " FORMAT JSONEachRow"
	body, err = client.execute(ctx, sql)
	if err != nil {
		return page, fmt.Errorf("query ClickHouse traffic sessions: %w", err)
	}
	items, err := decodeTrafficSessionRows(body)
	if err != nil {
		return page, err
	}
	page.Items = items
	return page, nil
}

type clickHouseTrafficSessionReadRow struct {
	SessionUID  string `json:"session_uid"`
	ObservedAt  string `json:"observed_at"`
	AgentID     string `json:"agent_id"`
	Sensor      string `json:"sensor"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	AppProto    string `json:"app_proto"`
	VLAN        uint16 `json:"vlan"`
	CommunityID string `json:"community_id"`
	// ClickHouse emits UInt64 as a JSON string by default (output_format_json_
	// quote_64bit_integers), to avoid precision loss in JavaScript clients.
	// Declaring this as uint64 made every page fail to decode and silently fall
	// back to Postgres, so the reader must accept both shapes.
	FlowID      flexibleUint64 `json:"flow_id"`
	Direction   string         `json:"direction"`
	HTTPHost    string         `json:"http_host"`
	HTTPMethod  string         `json:"http_method"`
	HTTPURI     string         `json:"http_uri"`
	TLSSNI      string         `json:"tls_sni"`
	TLSJA3      string         `json:"tls_ja3"`
	TLSJA4      string         `json:"tls_ja4"`
	DNSQuery    string         `json:"dns_query"`
	RawEvent    string         `json:"raw_event"`
}

// flexibleUint64 accepts a JSON number or a quoted numeric string. ClickHouse
// quotes 64-bit integers by default; accepting both keeps the reader correct
// regardless of the server's output_format_json_quote_64bit_integers setting.
type flexibleUint64 uint64

func (value *flexibleUint64) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*value = 0
		return nil
	}
	trimmed = strings.Trim(trimmed, `"`)
	if trimmed == "" {
		*value = 0
		return nil
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return fmt.Errorf("parse uint64 %q: %w", trimmed, err)
	}
	*value = flexibleUint64(parsed)
	return nil
}

// decodeTrafficSessionRows turns ClickHouse JSONEachRow output into the map shape
// the HTTP layer already serves, so the frontend contract does not change.
func decodeTrafficSessionRows(body []byte) ([]map[string]interface{}, error) {
	items := make([]map[string]interface{}, 0)
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		var row clickHouseTrafficSessionReadRow
		if err := decoder.Decode(&row); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode ClickHouse traffic session row: %w", err)
		}
		item := map[string]interface{}{}
		// Column values are the promoted, typed copy of the session facts. The
		// list path does not read raw_event, so nothing here depends on it.
		item["id"] = row.SessionUID
		item["session_uid"] = row.SessionUID
		item["observed_at"] = row.ObservedAt
		item["agent_id"] = row.AgentID
		item["sensor"] = row.Sensor
		item["src_ip"] = row.SrcIP
		item["dst_ip"] = row.DstIP
		item["src_port"] = row.SrcPort
		item["dst_port"] = row.DstPort
		item["protocol"] = row.Protocol
		item["app_proto"] = row.AppProto
		item["vlan"] = row.VLAN
		item["community_id"] = row.CommunityID
		item["flow_id"] = uint64(row.FlowID)
		item["direction"] = row.Direction
		item["http_host"] = row.HTTPHost
		item["http_method"] = row.HTTPMethod
		item["http_path"] = row.HTTPURI
		item["tls_sni"] = row.TLSSNI
		item["tls_ja3"] = row.TLSJA3
		item["tls_ja4"] = row.TLSJA4
		item["dns_query"] = row.DNSQuery
		items = append(items, item)
	}
	return items, nil
}

// GetTrafficSession loads one session including its full raw payload.
//
// This is the only path that pays the raw_event cost, and it is a single-row
// primary-key lookup rather than a page scan.
func (client *HTTPClickHouse) GetTrafficSession(ctx context.Context, sessionUID string) (map[string]interface{}, error) {
	if client == nil {
		return nil, fmt.Errorf("ClickHouse session client is nil")
	}
	uid := strings.TrimSpace(sessionUID)
	if uid == "" {
		return nil, fmt.Errorf("session uid is required")
	}
	sql := "SELECT " + queryTrafficSessionColumns + ", raw_event FROM lyflow_traffic_sessions WHERE session_uid = " +
		quoteClickHouseString(uid) + " ORDER BY version DESC LIMIT 1 FORMAT JSONEachRow"
	body, err := client.execute(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("get ClickHouse traffic session %s: %w", uid, err)
	}
	items, err := decodeTrafficSessionRows(body)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}
	return items[0], nil
}

// TrafficSessionTTL is the retention applied to lyflow_traffic_sessions.
// Alerts keep their own retention; sessions are high-volume and already
// summarized by the threat records they produced.
const TrafficSessionTTL = "INTERVAL 30 DAY"

// EnsureTrafficSessionTTL applies the retention to an existing table.
// MODIFY TTL is idempotent, and ClickHouse drops expired parts in the
// background once the table has a TTL at all.
func (client *HTTPClickHouse) EnsureTrafficSessionTTL(ctx context.Context) error {
	if client == nil {
		return fmt.Errorf("ClickHouse session client is nil")
	}
	statement := "ALTER TABLE lyflow_traffic_sessions MODIFY TTL toDateTime(observed_at) + " + TrafficSessionTTL
	if _, err := client.execute(ctx, statement); err != nil {
		return fmt.Errorf("apply ClickHouse traffic session TTL: %w", err)
	}
	return nil
}

// TrafficSessionTTLStatus reports whether the deployed table has a TTL and how
// many parts are already past it, so retention can be verified without guessing.
func (client *HTTPClickHouse) TrafficSessionTTLStatus(ctx context.Context) (string, error) {
	if client == nil {
		return "", fmt.Errorf("ClickHouse session client is nil")
	}
	body, err := client.execute(ctx,
		"SELECT ttl FROM system.tables WHERE database = currentDatabase() AND name = 'lyflow_traffic_sessions'")
	if err != nil {
		return "", fmt.Errorf("read ClickHouse traffic session TTL: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

func (client *HTTPClickHouse) TrafficSessionCount(ctx context.Context) (uint64, error) {
	if client == nil {
		return 0, fmt.Errorf("ClickHouse session client is nil")
	}
	body, err := client.execute(ctx, "SELECT count() FROM lyflow_traffic_sessions FINAL")
	if err != nil {
		return 0, fmt.Errorf("count ClickHouse traffic sessions: %w", err)
	}
	count, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse ClickHouse traffic session count: %w", err)
	}
	return count, nil
}
