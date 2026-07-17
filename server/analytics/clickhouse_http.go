package analytics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HTTPClickHouseConfig struct {
	Endpoint string
	Database string
	Username string
	Password string
	Timeout  time.Duration
	Client   *http.Client
}

type HTTPClickHouse struct {
	endpoint string
	username string
	password string
	client   *http.Client
}

func NewHTTPClickHouse(config HTTPClickHouseConfig) (*HTTPClickHouse, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("parse ClickHouse endpoint %q: %w", config.Endpoint, err)
	}
	if config.Database != "" {
		query := endpoint.Query()
		query.Set("database", config.Database)
		endpoint.RawQuery = query.Encode()
	}
	client := config.Client
	if client == nil {
		timeout := config.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &HTTPClickHouse{
		endpoint: endpoint.String(), username: config.Username, password: config.Password, client: client,
	}, nil
}

func (client *HTTPClickHouse) execute(ctx context.Context, query string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create ClickHouse request: %w", err)
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if client.username != "" {
		request.SetBasicAuth(client.username, client.password)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return nil, errors.Join(ErrStorageBackpressure, fmt.Errorf("query ClickHouse: %w", err))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, errors.Join(ErrStorageBackpressure, fmt.Errorf("read ClickHouse response: %w", err))
	}
	if response.StatusCode != http.StatusOK {
		queryErr := fmt.Errorf("ClickHouse status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
		if response.StatusCode == http.StatusInsufficientStorage || isDiskFullResponse(body) {
			return nil, errors.Join(ErrStorageBackpressure, ErrClickHouseDiskFull, queryErr)
		}
		return nil, errors.Join(ErrStorageBackpressure, queryErr)
	}
	return body, nil
}

func isDiskFullResponse(body []byte) bool {
	message := strings.ToLower(string(body))
	return strings.Contains(message, "no space left") || strings.Contains(message, "not enough space") ||
		strings.Contains(message, "cannot write") && strings.Contains(message, "space")
}

func (client *HTTPClickHouse) Insert(ctx context.Context, event EventRecord) error {
	row := clickHouseEventRow{
		EventUID: event.ID, Version: event.Version, Timestamp: event.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
		SourceModule: event.SourceModule, EventType: event.EventType, Severity: event.Severity,
		AgentID: event.AgentID, HostID: event.HostID, ChainID: event.ChainID, EntityID: event.EntityID,
		RawReference: event.RawReference, Message: event.Message, PayloadJSON: event.PayloadJSON,
	}
	payload, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("encode ClickHouse event %s: %w", event.ID, err)
	}
	query := "INSERT INTO lyflow_security_events FORMAT JSONEachRow\n" + string(payload)
	if _, err := client.execute(ctx, query); err != nil {
		return fmt.Errorf("insert ClickHouse event %s: %w", event.ID, err)
	}
	return nil
}

func (client *HTTPClickHouse) QueryFinal(ctx context.Context, limit int) ([]EventRecord, error) {
	query := ClickHouseFinalQuery + " LIMIT " + strconv.Itoa(limit) +
		" SETTINGS output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow"
	body, err := client.execute(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query finalized ClickHouse events: %w", err)
	}
	events := make([]EventRecord, 0, limit)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 2<<20)
	for scanner.Scan() {
		var row clickHouseEventRow
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("decode finalized ClickHouse event: %w", err)
		}
		timestamp, err := time.Parse("2006-01-02 15:04:05.000", row.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("parse ClickHouse event timestamp: %w", err)
		}
		events = append(events, row.event(timestamp.UTC()))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan finalized ClickHouse events: %w", err)
	}
	return events, nil
}

type clickHouseEventRow struct {
	EventUID     string `json:"event_uid"`
	Version      uint64 `json:"version"`
	Timestamp    string `json:"timestamp"`
	SourceModule string `json:"source_module"`
	EventType    string `json:"event_type"`
	Severity     string `json:"severity"`
	AgentID      string `json:"agent_id"`
	HostID       string `json:"host_id"`
	ChainID      string `json:"chain_id"`
	EntityID     string `json:"entity_id"`
	RawReference string `json:"raw_reference"`
	Message      string `json:"message"`
	PayloadJSON  string `json:"payload_json"`
}

func (row clickHouseEventRow) event(timestamp time.Time) EventRecord {
	return EventRecord{
		ID: row.EventUID, Version: row.Version, Timestamp: timestamp, SourceModule: row.SourceModule,
		EventType: row.EventType, Severity: row.Severity, AgentID: row.AgentID, HostID: row.HostID,
		ChainID: row.ChainID, EntityID: row.EntityID, RawReference: row.RawReference,
		Message: row.Message, PayloadJSON: row.PayloadJSON,
	}
}
