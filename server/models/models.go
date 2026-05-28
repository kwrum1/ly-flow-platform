package models

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event represents a normalized security event stored in PostgreSQL
type Event struct {
	ID             int64     `json:"id" db:"id"`
	Timestamp      time.Time `json:"timestamp" db:"timestamp"`
	EventType      string    `json:"event_type" db:"event_type"`
	Source         string    `json:"source" db:"source"`
	Severity       string    `json:"severity" db:"severity"`
	SrcIP          string    `json:"src_ip" db:"src_ip"`
	DstIP          string    `json:"dst_ip" db:"dst_ip"`
	SrcPort        int       `json:"src_port" db:"src_port"`
	DstPort        int       `json:"dst_port" db:"dst_port"`
	Protocol       string    `json:"protocol" db:"protocol"`
	Domain         string    `json:"domain" db:"domain"`
	Tags           []string  `json:"tags" db:"tags"`
	MitreTactic    string    `json:"mitre_tactic" db:"mitre_tactic"`
	MitreTechnique string    `json:"mitre_technique" db:"mitre_technique"`
	RawData        []byte    `json:"raw_data" db:"raw_data"`
	Metadata       []byte    `json:"metadata" db:"metadata"`
	Status         string    `json:"status" db:"status"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// Asset represents a managed asset
type Asset struct {
	ID        int64     `json:"id" db:"id"`
	Hostname  string    `json:"hostname" db:"hostname"`
	IP        string    `json:"ip" db:"ip"`
	OS        string    `json:"os" db:"os"`
	AgentID   string    `json:"agent_id" db:"agent_id"`
	Tags      []string  `json:"tags" db:"tags"`
	FirstSeen time.Time `json:"first_seen" db:"first_seen"`
	LastSeen  time.Time `json:"last_seen" db:"last_seen"`
	Metadata  []byte    `json:"metadata" db:"metadata"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID           int64      `json:"id" db:"id"`
	AssetID      int64      `json:"asset_id" db:"asset_id"`
	CVE          string     `json:"cve" db:"cve"`
	Severity     string     `json:"severity" db:"severity"`
	Scanner      string     `json:"scanner" db:"scanner"`
	Title        string     `json:"title" db:"title"`
	Description  string     `json:"description" db:"description"`
	Remediation  string     `json:"remediation" db:"remediation"`
	Status       string     `json:"status" db:"status"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	ResolvedAt   *time.Time `json:"resolved_at" db:"resolved_at"`
}

// Agent represents a registered security agent
type Agent struct {
	ID              int64     `json:"id" db:"id"`
	UUID            string    `json:"uuid" db:"uuid"`
	AgentKey        string    `json:"agent_key" db:"agent_key"`
	Hostname        string    `json:"hostname" db:"hostname"`
	IP              string    `json:"ip" db:"ip"`
	OS              string    `json:"os" db:"os"`
	AgentVersion    string    `json:"agent_version" db:"agent_version"`
	Status          string    `json:"status" db:"status"`
	TrafficEnabled  bool      `json:"traffic_enabled" db:"traffic_enabled"`
	HIDSEnabled     bool      `json:"hids_enabled" db:"hids_enabled"`
	RASPEnabled     bool      `json:"rasp_enabled" db:"rasp_enabled"`
	LastHeartbeat   time.Time `json:"last_heartbeat" db:"last_heartbeat"`
	EnrolledAt      time.Time `json:"enrolled_at" db:"enrolled_at"`
	ConnectionSince time.Time `json:"connection_since" db:"connection_since"`
}

// AlertInput represents input for creating an event from an alert
type AlertInput struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Signature string    `json:"signature"`
	Category  string    `json:"category"`
	Severity  uint8     `json:"severity"`
	Score     int       `json:"risk_score"`
	Status    string    `json:"status"`
	SensorID  string    `json:"sensor_id"`
	Domain    string    `json:"domain"`
}

// ToEvent converts AlertInput to Event
func (a *AlertInput) ToEvent() *Event {
	severity := "low"
	switch a.Severity {
	case 1:
		severity = "critical"
	case 2:
		severity = "high"
	case 3:
		severity = "medium"
	}

	return &Event{
		Timestamp: a.Timestamp,
		EventType: a.Type,
		Source:    a.SensorID,
		Severity:  severity,
		SrcIP:     a.SrcIP,
		DstIP:     a.DstIP,
		SrcPort:   int(a.SrcPort),
		DstPort:   int(a.DstPort),
		Protocol:  a.Protocol,
		Domain:    a.Domain,
		Tags:      []string{a.Category},
		Status:    a.Status,
	}
}

// DB wraps the pgx connection pool
type DB struct {
	pool *pgxpool.Pool
}

// NewDB creates a new database connection pool
func NewDB(ctx context.Context, dsn string) (*DB, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 20
	config.MinConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}

	return &DB{pool: pool}, nil
}

// Close closes the database connection pool
func (db *DB) Close(ctx context.Context) {
	db.pool.Close()
}

// InsertEvent inserts a new event into the database
func (db *DB) InsertEvent(ctx context.Context, event *Event) (int64, error) {
	var id int64
	var tags []string
	if event.Tags == nil {
		tags = []string{}
	} else {
		tags = event.Tags
	}

	query := `
		INSERT INTO events (timestamp, event_type, source, severity, src_ip, dst_ip,
			src_port, dst_port, protocol, domain, tags, mitre_tactic, mitre_technique,
			raw_data, metadata, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id
	`

	err := db.pool.QueryRow(ctx, query,
		event.Timestamp, event.EventType, event.Source, event.Severity,
		event.SrcIP, event.DstIP, event.SrcPort, event.DstPort,
		event.Protocol, event.Domain, tags, event.MitreTactic, event.MitreTechnique,
		event.RawData, event.Metadata, event.Status,
	).Scan(&id)

	return id, err
}

// BatchInsertEvents inserts multiple events in a batch
func (db *DB) BatchInsertEvents(ctx context.Context, events []*Event) error {
	batch := &pgx.Batch{}
	for _, event := range events {
		var tags []string
		if event.Tags == nil {
			tags = []string{}
		} else {
			tags = event.Tags
		}
		batch.Queue(`
			INSERT INTO events (timestamp, event_type, source, severity, src_ip, dst_ip,
				src_port, dst_port, protocol, domain, tags, mitre_tactic, mitre_technique,
				raw_data, metadata, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		`,
			event.Timestamp, event.EventType, event.Source, event.Severity,
			event.SrcIP, event.DstIP, event.SrcPort, event.DstPort,
			event.Protocol, event.Domain, tags, event.MitreTactic, event.MitreTechnique,
			event.RawData, event.Metadata, event.Status,
		)
	}

	br := db.pool.SendBatch(ctx, batch)
	defer br.Close()

	for range events {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}

	return nil
}

// GetEvents retrieves events with pagination and filtering
func (db *DB) GetEvents(ctx context.Context, limit, offset int, filters map[string]interface{}) ([]*Event, int, error) {
	countQuery := "SELECT COUNT(*) FROM events WHERE 1=1"
	selectQuery := `
		SELECT id, timestamp, event_type, source, severity, src_ip, dst_ip,
			src_port, dst_port, protocol, domain, tags, mitre_tactic, mitre_technique,
			raw_data, metadata, status, created_at
		FROM events WHERE 1=1
	`
	args := []interface{}{}
	argIdx := 1

	if severity, ok := filters["severity"].(string); ok && severity != "" {
		countQuery += " AND severity = $" + strconv.Itoa(argIdx)
		selectQuery += " AND severity = $" + strconv.Itoa(argIdx)
		args = append(args, severity)
		argIdx++
	}
	if eventType, ok := filters["event_type"].(string); ok && eventType != "" {
		countQuery += " AND event_type = $" + strconv.Itoa(argIdx)
		selectQuery += " AND event_type = $" + strconv.Itoa(argIdx)
		args = append(args, eventType)
		argIdx++
	}
	if status, ok := filters["status"].(string); ok && status != "" {
		countQuery += " AND status = $" + strconv.Itoa(argIdx)
		selectQuery += " AND status = $" + strconv.Itoa(argIdx)
		args = append(args, status)
		argIdx++
	}
	if srcIP, ok := filters["src_ip"].(string); ok && srcIP != "" {
		countQuery += " AND src_ip = $" + strconv.Itoa(argIdx)
		selectQuery += " AND src_ip = $" + strconv.Itoa(argIdx)
		args = append(args, srcIP)
		argIdx++
	}
	if dstIP, ok := filters["dst_ip"].(string); ok && dstIP != "" {
		countQuery += " AND dst_ip = $" + strconv.Itoa(argIdx)
		selectQuery += " AND dst_ip = $" + strconv.Itoa(argIdx)
		args = append(args, dstIP)
		argIdx++
	}

	selectQuery += " ORDER BY timestamp DESC"
	selectQuery += " LIMIT $" + strconv.Itoa(argIdx)
	args = append(args, limit)
	argIdx++
	selectQuery += " OFFSET $" + strconv.Itoa(argIdx)
	args = append(args, offset)

	var total int
	if err := db.pool.QueryRow(ctx, countQuery, args[:len(args)-2]...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		var e Event
		err := rows.Scan(
			&e.ID, &e.Timestamp, &e.EventType, &e.Source, &e.Severity,
			&e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort,
			&e.Protocol, &e.Domain, &e.Tags, &e.MitreTactic, &e.MitreTechnique,
			&e.RawData, &e.Metadata, &e.Status, &e.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, &e)
	}

	return events, total, nil
}

// GetEventByID retrieves a single event by ID
func (db *DB) GetEventByID(ctx context.Context, id int64) (*Event, error) {
	var e Event
	query := `
		SELECT id, timestamp, event_type, source, severity, src_ip, dst_ip,
			src_port, dst_port, protocol, domain, tags, mitre_tactic, mitre_technique,
			raw_data, metadata, status, created_at
		FROM events WHERE id = $1
	`
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&e.ID, &e.Timestamp, &e.EventType, &e.Source, &e.Severity,
		&e.SrcIP, &e.DstIP, &e.SrcPort, &e.DstPort,
		&e.Protocol, &e.Domain, &e.Tags, &e.MitreTactic, &e.MitreTechnique,
		&e.RawData, &e.Metadata, &e.Status, &e.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// UpdateEventStatus updates the status of an event
func (db *DB) UpdateEventStatus(ctx context.Context, id int64, status string) error {
	_, err := db.pool.Exec(ctx, "UPDATE events SET status = $1 WHERE id = $2", status, id)
	return err
}

// GetAssets retrieves assets with pagination
func (db *DB) GetAssets(ctx context.Context, limit, offset int) ([]*Asset, int, error) {
	var total int
	countQuery := "SELECT COUNT(*) FROM assets"
	if err := db.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, hostname, ip, os, agent_id, tags, first_seen, last_seen, metadata, created_at
		FROM assets ORDER BY last_seen DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := db.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assets []*Asset
	for rows.Next() {
		var a Asset
		err := rows.Scan(
			&a.ID, &a.Hostname, &a.IP, &a.OS, &a.AgentID,
			&a.Tags, &a.FirstSeen, &a.LastSeen, &a.Metadata, &a.CreatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		assets = append(assets, &a)
	}

	return assets, total, nil
}

// GetAssetByID retrieves a single asset by ID
func (db *DB) GetAssetByID(ctx context.Context, id int64) (*Asset, error) {
	var a Asset
	query := `
		SELECT id, hostname, ip, os, agent_id, tags, first_seen, last_seen, metadata, created_at
		FROM assets WHERE id = $1
	`
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&a.ID, &a.Hostname, &a.IP, &a.OS, &a.AgentID,
		&a.Tags, &a.FirstSeen, &a.LastSeen, &a.Metadata, &a.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetStats returns dashboard statistics
func (db *DB) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total events count
	var totalEvents int64
	err := db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&totalEvents)
	if err != nil {
		return nil, err
	}
	stats["total_events"] = totalEvents

	// Events by severity
	severityQuery := `
		SELECT severity, COUNT(*) as count
		FROM events
		GROUP BY severity
	`
	rows, err := db.pool.Query(ctx, severityQuery)
	if err != nil {
		return nil, err
	}
	severityStats := make(map[string]int64)
	for rows.Next() {
		var sev string
		var count int64
		if err := rows.Scan(&sev, &count); err == nil {
			severityStats[sev] = count
		}
	}
	rows.Close()
	stats["events_by_severity"] = severityStats

	// Events by type
	typeQuery := `
		SELECT event_type, COUNT(*) as count
		FROM events
		GROUP BY event_type
	`
	rows, err = db.pool.Query(ctx, typeQuery)
	if err != nil {
		return nil, err
	}
	typeStats := make(map[string]int64)
	for rows.Next() {
		var evtType string
		var count int64
		if err := rows.Scan(&evtType, &count); err == nil {
			typeStats[evtType] = count
		}
	}
	rows.Close()
	stats["events_by_type"] = typeStats

	// Recent events (last 24h)
	var recentEvents int64
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE timestamp > NOW() - INTERVAL '24 hours'").Scan(&recentEvents)
	if err != nil {
		return nil, err
	}
	stats["recent_events_24h"] = recentEvents

	// New events count
	var newEvents int64
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE status = 'new'").Scan(&newEvents)
	if err != nil {
		return nil, err
	}
	stats["new_events"] = newEvents

	// Total assets
	var totalAssets int64
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM assets").Scan(&totalAssets)
	if err != nil {
		return nil, err
	}
	stats["total_assets"] = totalAssets

	// Open vulnerabilities
	var openVulns int64
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'").Scan(&openVulns)
	if err != nil {
		return nil, err
	}
	stats["open_vulnerabilities"] = openVulns

	return stats, nil
}

// UpsertAsset creates or updates an asset
func (db *DB) UpsertAsset(ctx context.Context, asset *Asset) error {
	query := `
		INSERT INTO assets (hostname, ip, os, agent_id, tags, first_seen, last_seen, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (hostname) DO UPDATE SET
			ip = EXCLUDED.ip,
			os = EXCLUDED.os,
			last_seen = EXCLUDED.last_seen,
			tags = EXCLUDED.tags
	`
	_, err := db.pool.Exec(ctx, query,
		asset.Hostname, asset.IP, asset.OS, asset.AgentID,
		asset.Tags, asset.FirstSeen, asset.LastSeen, asset.Metadata,
	)
	return err
}

func (db *DB) CreateAgent(ctx context.Context, agent *Agent) error {
	query := `
		INSERT INTO agents (uuid, agent_key, hostname, ip, os, agent_version, status, traffic_enabled, hids_enabled, rasp_enabled, last_heartbeat, enrolled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		RETURNING id
	`
	return db.pool.QueryRow(ctx, query,
		agent.UUID, agent.AgentKey, agent.Hostname, agent.IP, agent.OS,
		agent.AgentVersion, agent.Status, agent.TrafficEnabled,
		agent.HIDSEnabled, agent.RASPEnabled, agent.LastHeartbeat,
	).Scan(&agent.ID)
}

func (db *DB) UpdateAgentHeartbeat(ctx context.Context, uuid string) error {
	query := `UPDATE agents SET last_heartbeat = NOW(), status = 'online' WHERE uuid = $1`
	_, err := db.pool.Exec(ctx, query, uuid)
	return err
}

func (db *DB) GetAgentByUUID(ctx context.Context, uuid string) (*Agent, error) {
	var a Agent
	query := `SELECT id, uuid, agent_key, hostname, ip, os, agent_version, status, traffic_enabled, hids_enabled, rasp_enabled, last_heartbeat, enrolled_at FROM agents WHERE uuid = $1`
	err := db.pool.QueryRow(ctx, query, uuid).Scan(&a.ID, &a.UUID, &a.AgentKey, &a.Hostname, &a.IP, &a.OS, &a.AgentVersion, &a.Status, &a.TrafficEnabled, &a.HIDSEnabled, &a.RASPEnabled, &a.LastHeartbeat, &a.EnrolledAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (db *DB) GetAllAgents(ctx context.Context) ([]*Agent, error) {
	query := `SELECT id, uuid, agent_key, hostname, ip, os, agent_version, status, traffic_enabled, hids_enabled, rasp_enabled, last_heartbeat, enrolled_at FROM agents ORDER BY enrolled_at DESC`
	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*Agent
	for rows.Next() {
		var a Agent
		err := rows.Scan(&a.ID, &a.UUID, &a.AgentKey, &a.Hostname, &a.IP, &a.OS, &a.AgentVersion, &a.Status,
			&a.TrafficEnabled, &a.HIDSEnabled, &a.RASPEnabled, &a.LastHeartbeat, &a.EnrolledAt)
		if err != nil {
			return nil, err
		}
		agents = append(agents, &a)
	}
	return agents, nil
}

func (db *DB) GetAgentStats(ctx context.Context) (total, online int64, err error) {
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM agents").Scan(&total)
	if err != nil {
		return
	}
	err = db.pool.QueryRow(ctx, "SELECT COUNT(*) FROM agents WHERE status = 'online'").Scan(&online)
	return
}

var _ = strconv.Itoa