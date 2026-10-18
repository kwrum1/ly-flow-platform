package analytics

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

const (
	DefaultEventV2QueryLimit = 50
	MaxEventV2QueryLimit     = 500
	MaxEventV2QueryRange     = 30 * 24 * time.Hour
)

type EventV2Query struct {
	From        time.Time
	To          time.Time
	Source      string
	EventType   string
	Severity    string
	Stage       string
	AssetID     string
	TechniqueID string
	Query       string
	Limit       int
	CursorAt    time.Time
	CursorUID   string
}

type EventV2View struct {
	EventUID      string                  `json:"event_uid"`
	CorrelationID string                  `json:"correlation_id,omitempty"`
	TenantID      string                  `json:"tenant_id"`
	Source        string                  `json:"source"`
	EventType     string                  `json:"event_type"`
	EventAt       time.Time               `json:"event_at"`
	ObservedAt    time.Time               `json:"observed_at"`
	IngestedAt    time.Time               `json:"ingested_at"`
	AssetID       string                  `json:"asset_id,omitempty"`
	UserID        string                  `json:"user_id,omitempty"`
	ProcessPID    int                     `json:"process_pid,omitempty"`
	ProcessExe    string                  `json:"process_exe,omitempty"`
	FileHash      string                  `json:"file_hash,omitempty"`
	SrcIP         string                  `json:"src_ip,omitempty"`
	DstIP         string                  `json:"dst_ip,omitempty"`
	SrcPort       uint16                  `json:"src_port,omitempty"`
	DstPort       uint16                  `json:"dst_port,omitempty"`
	Proto         string                  `json:"proto,omitempty"`
	RuleID        string                  `json:"rule_id,omitempty"`
	RuleSource    string                  `json:"rule_source,omitempty"`
	Severity      string                  `json:"severity"`
	Confidence    float32                 `json:"confidence,omitempty"`
	TacticID      string                  `json:"tactic_id,omitempty"`
	TechniqueID   string                  `json:"technique_id,omitempty"`
	Stage         string                  `json:"stage,omitempty"`
	Evidence      []contracts.EvidenceRef `json:"evidence,omitempty"`
	Payload       json.RawMessage         `json:"payload,omitempty"`
	Raw           contracts.RawRef        `json:"raw"`
}

type EventV2Page struct {
	Items      []EventV2View `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

func (query EventV2Query) normalized() (EventV2Query, error) {
	if query.To.IsZero() {
		query.To = time.Now().UTC()
	}
	if query.From.IsZero() {
		query.From = query.To.Add(-24 * time.Hour)
	}
	if query.To.Before(query.From) {
		return EventV2Query{}, fmt.Errorf("from must be before to")
	}
	if query.To.Sub(query.From) > MaxEventV2QueryRange {
		return EventV2Query{}, fmt.Errorf("time range exceeds 30 days")
	}
	if query.Limit <= 0 {
		query.Limit = DefaultEventV2QueryLimit
	}
	if query.Limit > MaxEventV2QueryLimit {
		query.Limit = MaxEventV2QueryLimit
	}
	return query, nil
}

func (client *HTTPClickHouse) QueryEventsV2(ctx context.Context, query EventV2Query) (EventV2Page, error) {
	query, err := query.normalized()
	if err != nil {
		return EventV2Page{}, err
	}
	conditions := []string{
		"event_at >= " + quoteClickHouseTime(query.From),
		"event_at <= " + quoteClickHouseTime(query.To),
	}
	appendStringFilter := func(column, value string) {
		if strings.TrimSpace(value) != "" {
			conditions = append(conditions, column+" = "+quoteClickHouseString(value))
		}
	}
	appendStringFilter("source", query.Source)
	appendStringFilter("event_type", query.EventType)
	appendStringFilter("severity", query.Severity)
	appendStringFilter("stage", query.Stage)
	appendStringFilter("asset_id", query.AssetID)
	appendStringFilter("technique_id", query.TechniqueID)
	if keyword := strings.TrimSpace(query.Query); keyword != "" {
		pattern := quoteClickHouseString(keyword)
		fields := []string{"src_ip", "dst_ip", "asset_id", "user_id", "process_exe", "file_hash", "rule_id", "event_type"}
		parts := make([]string, 0, len(fields))
		for _, field := range fields {
			parts = append(parts, fmt.Sprintf("positionCaseInsensitive(%s, %s) > 0", field, pattern))
		}
		conditions = append(conditions, "("+strings.Join(parts, " OR ")+")")
	}
	if !query.CursorAt.IsZero() {
		cursorAt := quoteClickHouseTime(query.CursorAt)
		cursorUID := quoteClickHouseString(query.CursorUID)
		conditions = append(conditions, fmt.Sprintf(
			"(event_at < %s OR (event_at = %s AND event_uid < %s))", cursorAt, cursorAt, cursorUID))
	}
	sql := "SELECT event_uid, correlation_id, tenant_id, source, event_type, " +
		"event_at, observed_at, ingested_at, asset_id, user_id, " +
		"process_pid, process_exe, file_hash, src_ip, dst_ip, src_port, dst_port, proto, " +
		"rule_id, rule_source, severity, confidence, tactic_id, technique_id, stage, " +
		"evidence_json, payload_json, raw_schema, raw_event_id, raw_sha256 " +
		"FROM lyflow_events_v2 WHERE " + strings.Join(conditions, " AND ") +
		" ORDER BY event_at DESC, event_uid DESC LIMIT " + strconv.Itoa(query.Limit+1) +
		" FORMAT JSONEachRow"
	body, err := client.execute(ctx, sql)
	if err != nil {
		return EventV2Page{}, fmt.Errorf("query ClickHouse v2 events: %w", err)
	}
	rows, err := decodeEventV2Rows(body)
	if err != nil {
		return EventV2Page{}, err
	}
	page := EventV2Page{Items: make([]EventV2View, 0, len(rows))}
	if len(rows) > query.Limit {
		rows = rows[:query.Limit]
		last := rows[len(rows)-1]
		lastAt, _ := parseClickHouseTime(last.EventAt)
		page.NextCursor = encodeEventV2Cursor(lastAt, last.EventUID)
	}
	for _, row := range rows {
		page.Items = append(page.Items, row.view())
	}
	return page, nil
}

func (client *HTTPClickHouse) GetEventV2(ctx context.Context, eventUID string) (EventV2View, error) {
	eventUID = strings.TrimSpace(eventUID)
	if eventUID == "" {
		return EventV2View{}, fmt.Errorf("event uid is required")
	}
	sql := "SELECT event_uid, correlation_id, tenant_id, source, event_type, " +
		"event_at, observed_at, ingested_at, asset_id, user_id, " +
		"process_pid, process_exe, file_hash, src_ip, dst_ip, src_port, dst_port, proto, " +
		"rule_id, rule_source, severity, confidence, tactic_id, technique_id, stage, " +
		"evidence_json, payload_json, raw_schema, raw_event_id, raw_sha256 " +
		"FROM lyflow_events_v2 WHERE event_uid = " + quoteClickHouseString(eventUID) +
		" ORDER BY event_at DESC LIMIT 1 FORMAT JSONEachRow"
	body, err := client.execute(ctx, sql)
	if err != nil {
		return EventV2View{}, fmt.Errorf("get ClickHouse v2 event: %w", err)
	}
	rows, err := decodeEventV2Rows(body)
	if err != nil {
		return EventV2View{}, err
	}
	if len(rows) == 0 {
		return EventV2View{}, ErrEventV2NotFound
	}
	return rows[0].view(), nil
}

var ErrEventV2NotFound = errors.New("event v2 not found")

type eventV2QueryRow struct {
	EventUID      string  `json:"event_uid"`
	CorrelationID string  `json:"correlation_id"`
	TenantID      string  `json:"tenant_id"`
	Source        string  `json:"source"`
	EventType     string  `json:"event_type"`
	EventAt       string  `json:"event_at"`
	ObservedAt    string  `json:"observed_at"`
	IngestedAt    string  `json:"ingested_at"`
	AssetID       string  `json:"asset_id"`
	UserID        string  `json:"user_id"`
	ProcessPID    int     `json:"process_pid"`
	ProcessExe    string  `json:"process_exe"`
	FileHash      string  `json:"file_hash"`
	SrcIP         string  `json:"src_ip"`
	DstIP         string  `json:"dst_ip"`
	SrcPort       uint16  `json:"src_port"`
	DstPort       uint16  `json:"dst_port"`
	Proto         string  `json:"proto"`
	RuleID        string  `json:"rule_id"`
	RuleSource    string  `json:"rule_source"`
	Severity      string  `json:"severity"`
	Confidence    float32 `json:"confidence"`
	TacticID      string  `json:"tactic_id"`
	TechniqueID   string  `json:"technique_id"`
	Stage         string  `json:"stage"`
	EvidenceJSON  string  `json:"evidence_json"`
	PayloadJSON   string  `json:"payload_json"`
	RawSchema     string  `json:"raw_schema"`
	RawEventID    string  `json:"raw_event_id"`
	RawSHA256     string  `json:"raw_sha256"`
}

func decodeEventV2Rows(body []byte) ([]eventV2QueryRow, error) {
	rows := make([]eventV2QueryRow, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row eventV2QueryRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("decode ClickHouse v2 event row: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (row eventV2QueryRow) view() EventV2View {
	view := EventV2View{
		EventUID:      row.EventUID,
		CorrelationID: row.CorrelationID,
		TenantID:      row.TenantID,
		Source:        row.Source,
		EventType:     row.EventType,
		AssetID:       row.AssetID,
		UserID:        row.UserID,
		ProcessPID:    row.ProcessPID,
		ProcessExe:    row.ProcessExe,
		FileHash:      row.FileHash,
		SrcIP:         row.SrcIP,
		DstIP:         row.DstIP,
		SrcPort:       row.SrcPort,
		DstPort:       row.DstPort,
		Proto:         row.Proto,
		RuleID:        row.RuleID,
		RuleSource:    row.RuleSource,
		Severity:      row.Severity,
		Confidence:    row.Confidence,
		TacticID:      row.TacticID,
		TechniqueID:   row.TechniqueID,
		Stage:         row.Stage,
		Raw: contracts.RawRef{
			NativeSchema: row.RawSchema, NativeEventID: row.RawEventID,
			PayloadSHA256: row.RawSHA256,
		},
	}
	view.EventAt, _ = parseClickHouseTime(row.EventAt)
	view.ObservedAt, _ = parseClickHouseTime(row.ObservedAt)
	view.IngestedAt, _ = parseClickHouseTime(row.IngestedAt)
	if row.EvidenceJSON != "" {
		_ = json.Unmarshal([]byte(row.EvidenceJSON), &view.Evidence)
	}
	if row.PayloadJSON != "" {
		view.Payload = json.RawMessage(row.PayloadJSON)
	}
	return view
}

func quoteClickHouseString(value string) string {
	escaped := strings.ReplaceAll(value, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "'", "\\'")
	return "'" + escaped + "'"
}

func quoteClickHouseTime(value time.Time) string {
	return quoteClickHouseString(value.UTC().Format("2006-01-02 15:04:05.000"))
}

func parseClickHouseTime(value string) (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05.000", value)
}

func encodeEventV2Cursor(at time.Time, uid string) string {
	payload, _ := json.Marshal(struct {
		At  string `json:"at"`
		UID string `json:"uid"`
	}{At: at.UTC().Format(time.RFC3339Nano), UID: uid})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func DecodeEventV2Cursor(value string) (time.Time, string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("decode cursor: %w", err)
	}
	var cursor struct {
		At  string `json:"at"`
		UID string `json:"uid"`
	}
	if err := json.Unmarshal(decoded, &cursor); err != nil {
		return time.Time{}, "", fmt.Errorf("decode cursor payload: %w", err)
	}
	at, err := time.Parse(time.RFC3339Nano, cursor.At)
	if err != nil || cursor.UID == "" {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	return at, cursor.UID, nil
}
