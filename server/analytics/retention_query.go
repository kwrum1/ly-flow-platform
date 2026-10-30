package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RetentionWindowQuery returns the oldest and newest stored v2 event together
// with the row count. It is the source of truth for the retention audit; a TTL
// configuration alone is not evidence that data is actually queryable.
const RetentionWindowQuery = `SELECT min(event_at) AS earliest, max(event_at) AS latest, count() AS rows FROM lyflow_events_v2 FORMAT JSONEachRow`

// QueryRetention implements the retention audit data access.
func (client *HTTPClickHouse) QueryRetention(ctx context.Context) (time.Time, time.Time, int64, error) {
	body, err := client.execute(ctx, RetentionWindowQuery)
	if err != nil {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("query retention window: %w", err)
	}
	line := strings.TrimSpace(string(body))
	if line == "" {
		return time.Time{}, time.Time{}, 0, nil
	}
	if index := strings.IndexByte(line, '\n'); index >= 0 {
		line = line[:index]
	}
	var row struct {
		Earliest string          `json:"earliest"`
		Latest   string          `json:"latest"`
		Rows     json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		return time.Time{}, time.Time{}, 0, fmt.Errorf("decode retention window: %w", err)
	}
	// ClickHouse quotes 64-bit integers in JSON by default, so accept both
	// a JSON number and a quoted string.
	rows := int64(0)
	if len(row.Rows) > 0 {
		if parsed, err := strconv.ParseInt(strings.Trim(string(row.Rows), `"`), 10, 64); err == nil {
			rows = parsed
		}
	}
	earliest, err := parseRetentionTime(row.Earliest)
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	latest, err := parseRetentionTime(row.Latest)
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	return earliest, latest, rows, nil
}

func parseRetentionTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "1970-01-01") || strings.HasPrefix(value, "0001-01-01") {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05.000", value); err == nil {
		return parsed.UTC(), nil
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized retention timestamp %q", value)
}
