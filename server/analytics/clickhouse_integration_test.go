package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClickHouseDuplicateUIDVersionsFinalizeToDeterministicRow(t *testing.T) {
	endpoint := os.Getenv("LYFLOW_TEST_CLICKHOUSE_HTTP")
	if endpoint == "" {
		t.Skip("LYFLOW_TEST_CLICKHOUSE_HTTP is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, query := range []string{
		"DROP TABLE IF EXISTS lyflow_events",
		EventTableDDL,
		`INSERT INTO lyflow_events (event_id, version, timestamp, source_module, event_type, severity, agent_id, host_id, chain_id, entity_id, raw_reference, message, payload_json) VALUES
('duplicate-uid', 2, '2026-07-13 12:00:02.000', 'security', 'alert', 'high', 'agent-1', 'host-1', '', '', '', 'version-2', '{"version":2}'),
('duplicate-uid', 1, '2026-07-13 12:00:01.000', 'security', 'alert', 'low', 'agent-1', 'host-1', '', '', '', 'version-1', '{"version":1}')`,
	} {
		if _, err := clickHouseHTTPQuery(ctx, endpoint, query); err != nil {
			t.Fatalf("prepare real ClickHouse duplicate rows: %v", err)
		}
	}
	query := strings.Replace(EventQuery, "LIMIT ?", "LIMIT 10", 1) + " FORMAT JSONEachRow"

	body, err := clickHouseHTTPQuery(ctx, endpoint, query)
	if err != nil {
		t.Fatalf("execute production finalized query: %v", err)
	}
	type finalizedRow struct {
		EventID string `json:"event_id"`
		Version uint64 `json:"version,string"`
		Message string `json:"message"`
	}
	var rows []finalizedRow
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		var row finalizedRow
		if err := decoder.Decode(&row); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode finalized ClickHouse row: %v", err)
		}
		rows = append(rows, row)
	}
	if len(rows) != 1 || rows[0].EventID != "duplicate-uid" || rows[0].Version != 2 || rows[0].Message != "version-2" {
		t.Fatalf("FINAL did not choose one deterministic highest-version row: %+v", rows)
	}
}

func clickHouseHTTPQuery(ctx context.Context, endpoint, query string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create ClickHouse request: %w", err)
	}
	request.SetBasicAuth(os.Getenv("LYFLOW_TEST_CLICKHOUSE_USER"), os.Getenv("LYFLOW_TEST_CLICKHOUSE_PASSWORD"))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query ClickHouse: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read ClickHouse response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ClickHouse status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
