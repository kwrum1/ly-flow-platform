package asset

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type AssetManager struct {
	assets map[string]*Host
	mu    sync.RWMutex
}

func NewAssetManager() *AssetManager {
	return &AssetManager{
		assets: make(map[string]*Host),
	}
}

func (am *AssetManager) Register(host *Host) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if host.ID == "" {
		host.ID = fmt.Sprintf("host-%d", time.Now().UnixNano())
	}
	am.assets[host.ID] = host
	return nil
}

func (am *AssetManager) Update(hostID string, updates map[string]interface{}) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	host, ok := am.assets[hostID]
	if !ok {
		return fmt.Errorf("资产不存在: %s", hostID)
	}
	host.LastSeen = time.Now()

	if hostname, ok := updates["hostname"].(string); ok {
		host.Hostname = hostname
	}
	if ip, ok := updates["ip"].(string); ok {
		host.IP = ip
	}
	if status, ok := updates["status"].(string); ok {
		host.Status = status
	}
	if tags, ok := updates["tags"].([]string); ok {
		host.Tags = append(host.Tags, tags...)
	}

	return nil
}

func (am *AssetManager) Get(hostID string) (*Host, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if host, ok := am.assets[hostID]; ok {
		return host, nil
	}
	return nil, fmt.Errorf("资产不存在: %s", hostID)
}

func (am *AssetManager) List(status, riskLevel, os string, limit int) []*Host {
	am.mu.RLock()
	defer am.mu.RUnlock()

	hosts := make([]*Host, 0)
	for _, host := range am.assets {
		if status != "" && host.Status != status {
			continue
		}
		if riskLevel != "" && host.RiskLevel != riskLevel {
			continue
		}
		if os != "" && host.OS != os {
			continue
		}
		hosts = append(hosts, host)
	}
	if limit > 0 && limit < len(hosts) {
		hosts = hosts[:limit]
	}
	return hosts
}

func (am *AssetManager) Delete(hostID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, ok := am.assets[hostID]; !ok {
		return fmt.Errorf("资产不存在: %s", hostID)
	}
	delete(am.assets, hostID)
	return nil
}

func (am *AssetManager) UpdateStats(hostID string, alertCount, vulnCount, raspBlocked int) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if host, ok := am.assets[hostID]; ok {
		host.AlertCount = alertCount
		host.VulnCount = vulnCount
		host.RASPBlocked = raspBlocked
		return nil
	}
	return fmt.Errorf("资产不存在: %s", hostID)
}

func (am *AssetManager) GetStats() *HostStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	stats := &HostStats{
		Total:   int64(len(am.assets)),
		Online:  0,
		Offline: 0,
		ByStatus: make(map[string]int64),
		ByRiskLevel: make(map[string]int64),
		ByOS: make(map[string]int64),
		TodayNew: 0,
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	for _, host := range am.assets {
		if host.Status == "online" {
			stats.Online++
		} else {
			stats.Offline++
		}
		stats.ByStatus[host.Status]++
		stats.ByRiskLevel[host.RiskLevel]++
		stats.ByOS[host.OS]++
		if host.FirstSeen.After(cutoff) {
			stats.TodayNew++
		}
		if host.RiskLevel == "critical" || host.RiskLevel == "high" {
			stats.Critical++
		}
		if host.VulnCount > 0 {
			stats.WithVulns++
		}
	}
	return stats
}

func (am *AssetManager) Heartbeat(req *HeartbeatRequest) (*Host, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	hostID := req.AgentID
	if hostID == "" {
		hostID = fmt.Sprintf("host-%s", req.Hostname)
	}

	host, exists := am.assets[hostID]
	if !exists {
		host = &Host{
			ID:    hostID,
			Status: "online",
			Tags:  []string{},
		}
		host.FirstSeen = time.Now()
		am.assets[hostID] = host
	}

	host.Hostname = req.Hostname
	host.IP = req.IP
	host.MAC = req.MAC
	host.OS = req.OS
	host.OSVersion = req.OSVersion
	host.Arch = req.Arch
	host.AgentVersion = req.AgentVersion
	host.CPU = req.CPU
	host.MemoryMB = req.MemoryMB
	host.DiskGB = req.DiskGB
	host.Status = "online"
	host.LastHeartbeat = time.Now()
	host.LastSeen = time.Now()
	host.Tags = req.Tags

	return host, nil
}

func (am *AssetManager) Search(query string) []*Host {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var results []*Host
	for _, host := range am.assets {
		if containsIgnoreCase(host.Hostname, query) ||
			containsIgnoreCase(host.IP, query) ||
			containsIgnoreCase(host.OS, query) {
			results = append(results, host)
		}
	}
	return results
}

func containsIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func (am *AssetManager) ToJSON() ([]byte, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	data := make([]*Host, 0, len(am.assets))
	for _, host := range am.assets {
		data = append(data, host)
	}
	return json.Marshal(data)
}

func (am *AssetManager) FromJSON(data []byte) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	var hosts []*Host
	if err := json.Unmarshal(data, &hosts); err != nil {
		return err
	}

	am.assets = make(map[string]*Host)
	for _, host := range hosts {
		am.assets[host.ID] = host
	}
	return nil
}
