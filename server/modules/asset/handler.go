package asset

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Handler struct {
	db *pgxpool.Pool
}

func NewHandler(db *pgxpool.Pool) *Handler {
	return &Handler{db: db}
}

type HostStats struct {
	Total            int64            `json:"total"`
	Online           int64            `json:"online"`
	Offline          int64            `json:"offline"`
	ByStatus         map[string]int64 `json:"by_status"`
	ByRiskLevel      map[string]int64 `json:"by_risk_level"`
	ByOS             map[string]int64 `json:"by_os"`
	Critical         int64            `json:"critical_assets"`
	WithVulns        int64            `json:"with_vulnerabilities"`
	TodayNew         int64            `json:"today_new"`
	WithRASP         int64            `json:"with_rasp"`
	TotalAlerts      int64            `json:"total_alerts"`
	TotalRASPBlocked int64            `json:"total_rasp_blocked"`
}

type Host struct {
	ID           string `json:"id"`
	Hostname     string `json:"hostname"`
	IP           string `json:"ip"`
	MAC          string `json:"mac,omitempty"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	AgentID      string `json:"agent_id,omitempty"`

	Status        string    `json:"status"`
	RiskLevel     string    `json:"risk_level"`
	LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`

	CPU                string     `json:"cpu,omitempty"`
	MemoryMB           int64      `json:"memory_mb,omitempty"`
	DiskGB             int64      `json:"disk_gb,omitempty"`
	CPUUsagePercent    *float64   `json:"cpu_usage_percent,omitempty"`
	MemoryUsedMB       *int64     `json:"memory_used_mb,omitempty"`
	MemoryUsagePercent *float64   `json:"memory_usage_percent,omitempty"`
	DiskUsedGB         *int64     `json:"disk_used_gb,omitempty"`
	DiskUsagePercent   *float64   `json:"disk_usage_percent,omitempty"`
	MetricsUpdatedAt   *time.Time `json:"metrics_updated_at,omitempty"`

	Tags       []string `json:"tags,omitempty"`
	GroupID    string   `json:"group_id,omitempty"`
	Department string   `json:"department,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	Importance string   `json:"importance,omitempty"`

	AlertCount  int `json:"alert_count"`
	VulnCount   int `json:"vuln_count"`
	RASPBlocked int `json:"rasp_blocked"`

	Capabilities     map[string]interface{} `json:"capabilities,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Interfaces       []interface{}          `json:"interfaces,omitempty"`
	ListeningPorts   []interface{}          `json:"listening_ports,omitempty"`
	ProcessCount     int                    `json:"process_count"`
	TopologyID       string                 `json:"topology_id,omitempty"`
	MetricsFreshness string                 `json:"metrics_freshness,omitempty"`
}

type HostOverview struct {
	Host             Host                     `json:"host"`
	RecentAlerts     []map[string]interface{} `json:"recent_alerts"`
	RecentRASPAlerts []map[string]interface{} `json:"recent_rasp_alerts"`
	Performance      *PerformanceSummary      `json:"performance,omitempty"`
	RASPStats        *RASPStats               `json:"rasp_stats,omitempty"`
}

type PerformanceSummary struct {
	CPUPercent      float64 `json:"cpu_percent"`
	MemoryPercent   float64 `json:"memory_percent"`
	DiskPercent     float64 `json:"disk_percent"`
	LoadAvg1        float64 `json:"load_avg_1"`
	LoadAvg5        float64 `json:"load_avg_5"`
	NetworkInBytes  int64   `json:"network_in_bytes"`
	NetworkOutBytes int64   `json:"network_out_bytes"`
}

type RASPStats struct {
	TotalEvents  int64            `json:"total_events"`
	TodayEvents  int64            `json:"today_events"`
	Blocked      int64            `json:"blocked"`
	ByAttackType map[string]int64 `json:"by_attack_type"`
}

type NetworkInterface struct {
	Name    string `json:"name"`
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Netmask string `json:"netmask,omitempty"`
	State   string `json:"state,omitempty"`
}

type Port struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	State       string `json:"state"`
	Service     string `json:"service,omitempty"`
	Banner      string `json:"banner,omitempty"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

type Process struct {
	PID        int       `json:"pid"`
	PPID       int       `json:"ppid,omitempty"`
	Name       string    `json:"name"`
	Path       string    `json:"path,omitempty"`
	User       string    `json:"user,omitempty"`
	CMDLine    string    `json:"cmdline,omitempty"`
	CPUPercent float64   `json:"cpu_percent,omitempty"`
	MemoryMB   int64     `json:"memory_mb,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
}

type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
}

type Container struct {
	ContainerID string    `json:"container_id"`
	Name        string    `json:"name"`
	Image       string    `json:"image"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at"`
}

type HostGroup struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ParentID    string `json:"parent_id,omitempty"`
	HostCount   int    `json:"host_count"`
}

type HeartbeatRequest struct {
	AgentID           string             `json:"agent_id"`
	Hostname          string             `json:"hostname"`
	IP                string             `json:"ip"`
	MAC               string             `json:"mac"`
	OS                string             `json:"os"`
	OSVersion         string             `json:"os_version"`
	Arch              string             `json:"arch"`
	AgentVersion      string             `json:"agent_version"`
	CPU               string             `json:"cpu"`
	MemoryMB          int64              `json:"memory_mb"`
	DiskGB            int64              `json:"disk_gb"`
	NetworkInterfaces []NetworkInterface `json:"network_interfaces"`
	OpenPorts         []Port             `json:"open_ports"`
	Processes         []Process          `json:"processes"`
	Software          []Software         `json:"software"`
	Containers        []Container        `json:"containers,omitempty"`
	Tags              []string           `json:"tags"`
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	stats := &HostStats{
		ByStatus:    map[string]int64{},
		ByRiskLevel: map[string]int64{},
		ByOS:        map[string]int64{},
	}

	_ = h.db.QueryRow(ctx, "SELECT COUNT(*) FROM hosts").Scan(&stats.Total)
	_ = h.db.QueryRow(ctx, "SELECT COUNT(*) FROM hosts WHERE status = 'online'").Scan(&stats.Online)
	stats.Offline = stats.Total - stats.Online

	rows, err := h.db.Query(ctx, "SELECT status, COUNT(*) FROM hosts GROUP BY status")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var status string
			var count int64
			if rows.Scan(&status, &count) == nil {
				stats.ByStatus[status] = count
			}
		}
	}

	rows, err = h.db.Query(ctx, "SELECT COALESCE(risk_level, 'unknown'), COUNT(*) FROM hosts GROUP BY COALESCE(risk_level, 'unknown')")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var risk string
			var count int64
			if rows.Scan(&risk, &count) == nil {
				stats.ByRiskLevel[risk] = count
				if risk == "critical" {
					stats.Critical = count
				}
			}
		}
	}

	rows, err = h.db.Query(ctx, "SELECT COALESCE(os, 'unknown'), COUNT(*) FROM hosts GROUP BY COALESCE(os, 'unknown')")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var osName string
			var count int64
			if rows.Scan(&osName, &count) == nil {
				stats.ByOS[osName] = count
			}
		}
	}

	_ = h.db.QueryRow(ctx, "SELECT COALESCE(SUM(vuln_count), 0) FROM hosts").Scan(&stats.WithVulns)
	_ = h.db.QueryRow(ctx, "SELECT COUNT(*) FROM hosts WHERE DATE(first_seen) = CURRENT_DATE").Scan(&stats.TodayNew)
	_ = h.db.QueryRow(ctx, "SELECT COUNT(*) FROM hosts WHERE COALESCE(agent_id, '') <> ''").Scan(&stats.WithRASP)
	_ = h.db.QueryRow(ctx, "SELECT COALESCE(SUM(alert_count), 0) FROM hosts").Scan(&stats.TotalAlerts)
	_ = h.db.QueryRow(ctx, "SELECT COALESCE(SUM(rasp_blocked), 0) FROM hosts").Scan(&stats.TotalRASPBlocked)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": stats,
	})
}

func (h *Handler) ListHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	status := strings.TrimSpace(r.URL.Query().Get("status"))
	riskLevel := strings.TrimSpace(r.URL.Query().Get("risk_level"))
	osName := strings.TrimSpace(r.URL.Query().Get("os"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))

	ctx := r.Context()
	if err := syncAgentBackedHostStatus(ctx, h.db); err != nil {
		http.Error(w, "status sync failed", http.StatusInternalServerError)
		return
	}
	where := []string{"1=1"}
	args := make([]interface{}, 0, 8)
	argPos := 1

	if status != "" {
		where = append(where, "status = $"+strconv.Itoa(argPos))
		args = append(args, status)
		argPos++
	}
	if riskLevel != "" {
		where = append(where, "risk_level = $"+strconv.Itoa(argPos))
		args = append(args, riskLevel)
		argPos++
	}
	if osName != "" {
		where = append(where, "os = $"+strconv.Itoa(argPos))
		args = append(args, osName)
		argPos++
	}
	if search != "" {
		where = append(where, "(hostname ILIKE $"+strconv.Itoa(argPos)+" OR ip ILIKE $"+strconv.Itoa(argPos)+")")
		args = append(args, "%"+search+"%")
		argPos++
	}

	countQuery := "SELECT COUNT(*) FROM hosts WHERE " + strings.Join(where, " AND ")
	var total int64
	_ = h.db.QueryRow(ctx, countQuery, args...).Scan(&total)

	listQuery := "SELECT id, hostname, ip, COALESCE(mac, ''), COALESCE(os, ''), COALESCE(os_version, ''), COALESCE(arch, ''), COALESCE(agent_version, ''), COALESCE(agent_id, ''), COALESCE(status, 'offline'), COALESCE(risk_level, 'low'), COALESCE(last_heartbeat, NOW()), COALESCE(first_seen, NOW()), COALESCE(last_seen, NOW()), COALESCE(cpu, ''), COALESCE(memory_mb, 0), COALESCE(disk_gb, 0), COALESCE(tags, ARRAY[]::text[]), COALESCE(group_id, ''), COALESCE(department, ''), COALESCE(owner, ''), COALESCE(importance, ''), COALESCE(alert_count, 0), COALESCE(vuln_count, 0), COALESCE(rasp_blocked, 0), COALESCE(metadata, '{}'::jsonb) FROM hosts WHERE " + strings.Join(where, " AND ") + " ORDER BY last_seen DESC LIMIT $" + strconv.Itoa(argPos) + " OFFSET $" + strconv.Itoa(argPos+1)
	args = append(args, limit, offset)

	rows, err := h.db.Query(ctx, listQuery, args...)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	hosts := make([]*Host, 0, limit)
	for rows.Next() {
		var host Host
		var metadataRaw []byte
		if err := rows.Scan(&host.ID, &host.Hostname, &host.IP, &host.MAC, &host.OS, &host.OSVersion, &host.Arch, &host.AgentVersion, &host.AgentID, &host.Status, &host.RiskLevel, &host.LastHeartbeat, &host.FirstSeen, &host.LastSeen, &host.CPU, &host.MemoryMB, &host.DiskGB, &host.Tags, &host.GroupID, &host.Department, &host.Owner, &host.Importance, &host.AlertCount, &host.VulnCount, &host.RASPBlocked, &metadataRaw); err == nil {
			applyHostMetadata(&host, metadataRaw)
			hosts = append(hosts, &host)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	data := map[string]interface{}{
		"items":  hosts,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}
	if total == 0 {
		data["empty_state"] = map[string]string{
			"reason":  "NO_AGENTS",
			"message": "暂无 Agent 或资产数据",
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": data,
	})
}

func (h *Handler) GetHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	hostID := path[len("/api/v1/assets/"):]
	if idx := len("/api/v1/assets/"); idx > 0 {
		hostID = path[idx:]
	}

	if hostID == "overview" || hostID == "fingerprints" || hostID == "ports" ||
		hostID == "processes" || hostID == "software" || hostID == "containers" {
		http.Error(w, "Invalid endpoint", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if err := syncAgentBackedHostStatus(ctx, h.db); err != nil {
		http.Error(w, "status sync failed", http.StatusInternalServerError)
		return
	}
	host := &Host{}
	var metadataRaw []byte
	err := h.db.QueryRow(ctx, `
		SELECT id, hostname, ip, COALESCE(mac, ''), COALESCE(os, ''), COALESCE(os_version, ''), COALESCE(arch, ''),
			COALESCE(agent_version, ''), COALESCE(agent_id, ''), COALESCE(status, 'offline'), COALESCE(risk_level, 'low'),
			COALESCE(last_heartbeat, NOW()), COALESCE(first_seen, NOW()), COALESCE(last_seen, NOW()), COALESCE(cpu, ''),
			COALESCE(memory_mb, 0), COALESCE(disk_gb, 0), COALESCE(tags, ARRAY[]::text[]), COALESCE(group_id, ''),
			COALESCE(department, ''), COALESCE(owner, ''), COALESCE(importance, ''), COALESCE(alert_count, 0),
			COALESCE(vuln_count, 0), COALESCE(rasp_blocked, 0), COALESCE(metadata, '{}'::jsonb)
		FROM hosts WHERE id = $1
	`, hostID).Scan(
		&host.ID, &host.Hostname, &host.IP, &host.MAC, &host.OS, &host.OSVersion, &host.Arch,
		&host.AgentVersion, &host.AgentID, &host.Status, &host.RiskLevel,
		&host.LastHeartbeat, &host.FirstSeen, &host.LastSeen, &host.CPU,
		&host.MemoryMB, &host.DiskGB, &host.Tags, &host.GroupID,
		&host.Department, &host.Owner, &host.Importance, &host.AlertCount,
		&host.VulnCount, &host.RASPBlocked, &metadataRaw,
	)
	if err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if len(metadataRaw) > 0 {
		applyHostMetadata(host, metadataRaw)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": host,
	})
}

func syncAgentBackedHostStatus(ctx context.Context, db *pgxpool.Pool) error {
	if db == nil {
		return nil
	}
	if _, err := db.Exec(ctx, `UPDATE agents SET status='offline' WHERE status='online' AND last_heartbeat < NOW() - INTERVAL '5 minutes'`); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `
		UPDATE hosts h
		SET status = COALESCE(a.status, h.status),
			last_heartbeat = COALESCE(a.last_heartbeat, h.last_heartbeat),
			updated_at = NOW()
		FROM agents a
		WHERE h.agent_id = a.uuid
		  AND (h.status IS DISTINCT FROM a.status OR h.last_heartbeat IS DISTINCT FROM a.last_heartbeat)
	`)
	return err
}

func applyHostMetadata(host *Host, metadataRaw []byte) {
	if len(metadataRaw) == 0 {
		return
	}
	_ = json.Unmarshal(metadataRaw, &host.Metadata)
	if capabilities, ok := host.Metadata["capabilities"].(map[string]interface{}); ok {
		host.Capabilities = capabilities
	}
	if interfaces, ok := host.Metadata["interfaces"].([]interface{}); ok {
		host.Interfaces = interfaces
	}
	if ports, ok := host.Metadata["listening_ports"].([]interface{}); ok {
		host.ListeningPorts = ports
	}
	host.ProcessCount = int(int64FromInterface(host.Metadata["process_count"]))
	if host.ProcessCount == 0 {
		if processes, ok := host.Metadata["processes"].([]interface{}); ok {
			host.ProcessCount = len(processes)
		}
	}
	if host.AgentID != "" {
		host.TopologyID = "agent:" + host.AgentID
	} else {
		host.TopologyID = "host:" + host.ID
	}
	if rawMetricsAt, ok := host.Metadata["metrics_updated_at"]; ok {
		if parsed := parseMetadataTime(rawMetricsAt); parsed != nil {
			host.MetricsUpdatedAt = parsed
		}
	}
	host.MetricsFreshness = metricsFreshness(host.MetricsUpdatedAt, host.LastHeartbeat)
	perf, ok := host.Metadata["performance"].(map[string]interface{})
	if !ok {
		return
	}
	if cores := int64FromInterface(perf["cpu_cores"]); cores > 0 {
		host.CPU = strconv.FormatInt(cores, 10) + " cores"
	}
	if cpuPercent, ok := floatFromInterface(perf["cpu_usage_percent"]); ok {
		host.CPUUsagePercent = &cpuPercent
	}
	if loadAvg, ok := perf["load_avg"].([]interface{}); ok && len(loadAvg) > 0 {
		if load1, ok := floatFromInterface(loadAvg[0]); ok {
			cpuPercent := load1
			if cores := int64FromInterface(perf["cpu_cores"]); cores > 0 {
				cpuPercent = (load1 / float64(cores)) * 100
			}
			if host.CPUUsagePercent == nil {
				host.CPUUsagePercent = &cpuPercent
			}
		}
	}
	if memory, ok := perf["memory"].(map[string]interface{}); ok {
		total := int64FromInterface(memory["MemTotal"])
		available := int64FromInterface(memory["MemAvailable"])
		if total > 0 {
			host.MemoryMB = total / 1024 / 1024
			used := total - available
			usedMB := used / 1024 / 1024
			host.MemoryUsedMB = &usedMB
			usage := (float64(used) / float64(total)) * 100
			host.MemoryUsagePercent = &usage
		}
	}
	if disk, ok := perf["disk"].(map[string]interface{}); ok {
		total := int64FromInterface(disk["total_bytes"])
		free := int64FromInterface(disk["free_bytes"])
		if total > 0 {
			host.DiskGB = total / 1024 / 1024 / 1024
			used := total - free
			usedGB := used / 1024 / 1024 / 1024
			host.DiskUsedGB = &usedGB
			usage := (float64(used) / float64(total)) * 100
			host.DiskUsagePercent = &usage
		}
	}
	host.MetricsFreshness = metricsFreshness(host.MetricsUpdatedAt, host.LastHeartbeat)
}

func parseMetadataTime(value interface{}) *time.Time {
	switch v := value.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
				utc := parsed.UTC()
				return &utc
			}
		}
	case time.Time:
		utc := v.UTC()
		return &utc
	}
	return nil
}

func metricsFreshness(metricsAt *time.Time, heartbeat time.Time) string {
	reference := heartbeat
	if metricsAt != nil && !metricsAt.IsZero() {
		reference = *metricsAt
	}
	if reference.IsZero() {
		return "unknown"
	}
	age := time.Since(reference)
	switch {
	case age <= 2*time.Minute:
		return "fresh"
	case age <= 15*time.Minute:
		return "stale"
	default:
		return "expired"
	}
}

func int64FromInterface(v interface{}) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		value, _ := n.Int64()
		return value
	default:
		return 0
	}
}

func floatFromInterface(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		value, err := n.Float64()
		return value, err == nil
	default:
		return 0, false
	}
}

func (h *Handler) GetHostOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	hostID := path[len("/api/v1/assets/") : len(path)-len("/overview")]

	overview := &HostOverview{
		Host: Host{
			ID:          hostID,
			Hostname:    "web-server-01",
			IP:          "10.0.0.10",
			OS:          "linux",
			Status:      "online",
			RiskLevel:   "medium",
			AlertCount:  3,
			VulnCount:   5,
			RASPBlocked: 12,
		},
		RecentAlerts: []map[string]interface{}{
			{"id": "alert-001", "type": "hids", "severity": "high", "title": "可疑SSH登录", "time": "2024-01-15 14:30:00"},
			{"id": "alert-002", "type": "hids", "severity": "medium", "title": "端口扫描检测", "time": "2024-01-15 13:20:00"},
		},
		RecentRASPAlerts: []map[string]interface{}{
			{"id": "rasp-001", "attack_type": "sql_injection", "severity": "high", "blocked": true, "time": "2024-01-15 14:25:00"},
		},
		Performance: &PerformanceSummary{
			CPUPercent:    35.5,
			MemoryPercent: 62.3,
			DiskPercent:   45.2,
			LoadAvg1:      1.25,
			LoadAvg5:      0.98,
		},
		RASPStats: &RASPStats{
			TotalEvents: 156,
			TodayEvents: 12,
			Blocked:     89,
			ByAttackType: map[string]int64{
				"sql_injection":     45,
				"xss":               34,
				"command_injection": 21,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": overview,
	})
}

func (h *Handler) GetHostFingerprints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fingerprints := map[string]interface{}{
		"overview": map[string]interface{}{
			"hostname":     "web-server-01",
			"ip":           "10.0.0.10",
			"mac":          "00:0c:29:12:34:56",
			"os":           "Ubuntu 22.04",
			"os_version":   "5.15.0-91-generic",
			"arch":         "x86_64",
			"cpu":          "Intel(R) Xeon(R) CPU @ 2.40GHz (8 cores)",
			"memory_total": "16 GB",
			"disk_total":   "500 GB",
			"boot_time":    "2024-01-10 08:00:00",
			"uptime_days":  5,
		},
		"network": []NetworkInterface{
			{Name: "eth0", MAC: "00:0c:29:12:34:56", IP: "10.0.0.10", Netmask: "255.255.255.0", State: "up"},
			{Name: "lo", MAC: "00:00:00:00:00:00", IP: "127.0.0.1", Netmask: "255.0.0.0", State: "up"},
		},
		"docker": []Container{
			{ContainerID: "abc123", Name: "nginx-proxy", Image: "nginx:latest", Status: "running"},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": fingerprints,
	})
}

func (h *Handler) GetHostPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ports := []Port{
		{Port: 22, Protocol: "tcp", State: "open", Service: "ssh", PID: 1234, ProcessName: "sshd"},
		{Port: 80, Protocol: "tcp", State: "open", Service: "http", PID: 2345, ProcessName: "nginx"},
		{Port: 443, Protocol: "tcp", State: "open", Service: "https", PID: 2345, ProcessName: "nginx"},
		{Port: 3306, Protocol: "tcp", State: "open", Service: "mysql", PID: 3456, ProcessName: "mysqld"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"items": ports, "total": len(ports)},
	})
}

func (h *Handler) GetHostProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	processes := []Process{
		{PID: 1, Name: "systemd", Path: "/sbin/init", User: "root", CMDLine: "/sbin/init", CPUPercent: 0.1, MemoryMB: 12},
		{PID: 1234, Name: "sshd", Path: "/usr/sbin/sshd", User: "root", CMDLine: "/usr/sbin/sshd -D", CPUPercent: 0.2, MemoryMB: 5},
		{PID: 2345, Name: "nginx", Path: "/usr/sbin/nginx", User: "www-data", CMDLine: "nginx: worker process", CPUPercent: 1.5, MemoryMB: 50},
		{PID: 3456, Name: "mysqld", Path: "/usr/sbin/mysqld", User: "mysql", CMDLine: "/usr/sbin/mysqld", CPUPercent: 2.3, MemoryMB: 256},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"items": processes, "total": len(processes)},
	})
}

func (h *Handler) GetHostSoftware(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	software := []Software{
		{Name: "openssl", Version: "3.0.2-0ubuntu1.10"},
		{Name: "nginx", Version: "1.22.0"},
		{Name: "mysql-server", Version: "8.0.35"},
		{Name: "python3", Version: "3.10.12"},
		{Name: "openssh-server", Version: "8.9p1"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"items": software, "total": len(software)},
	})
}

func (h *Handler) CreateHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	hostID := "host-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	host := &Host{
		ID:           hostID,
		Hostname:     req.Hostname,
		IP:           req.IP,
		MAC:          req.MAC,
		OS:           req.OS,
		OSVersion:    req.OSVersion,
		Arch:         req.Arch,
		AgentVersion: req.AgentVersion,
		Status:       "online",
		RiskLevel:    "low",
		CPU:          req.CPU,
		MemoryMB:     req.MemoryMB,
		DiskGB:       req.DiskGB,
		Tags:         req.Tags,
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": host,
	})
}

func (h *Handler) UpdateHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": req,
	})
}

func (h *Handler) DeleteHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
	})
}

func (h *Handler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"agent_id":       req.AgentID,
			"received":       true,
			"next_heartbeat": 30,
		},
	})
}

func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": []HostGroup{},
	})
}
