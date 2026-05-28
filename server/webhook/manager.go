package webhook

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/model"
)

// Manager manages webhook configurations and message dispatching
type Manager struct {
	clients   map[string]*Client
	channels  map[string][]*WebhookConfig
	mu        sync.RWMutex
}

// WebhookConfig represents a webhook configuration
type WebhookConfig struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Type    string      `json:"type"` // dingtalk/wecom/feishu/custom
	URL     string      `json:"url"`
	Enabled bool        `json:"enabled"`
	Filters AlertFilter `json:"filters"`
}

// AlertFilter defines filtering criteria for alerts
type AlertFilter struct {
	Severity []string `json:"severity"` // critical/high/medium/low
	Category []string `json:"category"` // attack type categories
	Tags     []string `json:"tags"`     // custom tags
}

// NewManager creates a new webhook manager
func NewManager() *Manager {
	return &Manager{
		clients:  make(map[string]*Client),
		channels: make(map[string][]*WebhookConfig),
	}
}

// NewManagerWithClient creates a new webhook manager with a custom client
func NewManagerWithClient(client *Client) *Manager {
	m := NewManager()
	m.clients["default"] = client
	return m
}

// GetClient returns or creates a client for the given ID
func (m *Manager) GetClient(id string) *Client {
	m.mu.RLock()
	client, exists := m.clients[id]
	m.mu.RUnlock()

	if exists {
		return client
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if client, exists = m.clients[id]; exists {
		return client
	}

	client = NewClient()
	m.clients[id] = client
	return client
}

// AddWebhook adds a new webhook configuration
func (m *Manager) AddWebhook(config *WebhookConfig) error {
	if config.ID == "" {
		return fmt.Errorf("webhook ID cannot be empty")
	}
	if config.URL == "" {
		return fmt.Errorf("webhook URL cannot be empty")
	}
	if config.Type == "" {
		config.Type = "custom"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if webhook already exists
	for i, existing := range m.channels[config.Type] {
		if existing.ID == config.ID {
			m.channels[config.Type][i] = config
			return nil
		}
	}

	// Add new webhook
	m.channels[config.Type] = append(m.channels[config.Type], config)
	return nil
}

// RemoveWebhook removes a webhook configuration by ID and type
func (m *Manager) RemoveWebhook(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for webhookType, webhooks := range m.channels {
		for i, w := range webhooks {
			if w.ID == id {
				m.channels[webhookType] = append(webhooks[:i], webhooks[i+1:]...)
				return nil
			}
		}
	}

	return fmt.Errorf("webhook not found: %s", id)
}

// GetWebhook retrieves a webhook configuration by ID
func (m *Manager) GetWebhook(id string) (*WebhookConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, webhooks := range m.channels {
		for _, w := range webhooks {
			if w.ID == id {
				return w, nil
			}
		}
	}

	return nil, fmt.Errorf("webhook not found: %s", id)
}

// ListWebhooks returns all webhook configurations
func (m *Manager) ListWebhooks() []*WebhookConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*WebhookConfig
	for _, webhooks := range m.channels {
		result = append(result, webhooks...)
	}
	return result
}

// EnableWebhook enables or disables a webhook by ID
func (m *Manager) EnableWebhook(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, webhooks := range m.channels {
		for _, w := range webhooks {
			if w.ID == id {
				w.Enabled = enabled
				return nil
			}
		}
	}

	return fmt.Errorf("webhook not found: %s", id)
}

// SendAlert sends an alert to all matching webhooks
func (m *Manager) SendAlert(alert *model.Alert) error {
	webhookAlert := &Alert{
		ID:         strconv.FormatUint(alert.ID, 10),
		Severity:   model.SeverityFromUint8(alert.Severity),
		Category:   alert.Category,
		SourceIP:   alert.SrcIP,
		TargetIP:   alert.DstIP,
		Domain:     alert.Domain,
		Signature:  alert.Signature,
		Tags:       []string{alert.Category},
		Timestamp:  alert.Timestamp,
		Metadata: map[string]interface{}{
			"protocol":  alert.Protocol,
			"src_port":  alert.SrcPort,
			"dst_port":  alert.DstPort,
			"risk_score": alert.Score,
			"sensor_id":  alert.SensorID,
			"status":     alert.Status,
		},
	}

	return m.sendAlertToWebhooks(webhookAlert)
}

// sendAlertToWebhooks sends an alert to all matching webhook configurations
func (m *Manager) sendAlertToWebhooks(alert *Alert) error {
	m.mu.RLock()
	var matchingWebhooks []*WebhookConfig
	for _, webhooks := range m.channels {
		for _, w := range webhooks {
			if w.Enabled && m.matchesFilter(alert, &w.Filters) {
				matchingWebhooks = append(matchingWebhooks, w)
			}
		}
	}
	m.mu.RUnlock()

	if len(matchingWebhooks) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(matchingWebhooks))

	for _, w := range matchingWebhooks {
		wg.Add(1)
		go func(webhook *WebhookConfig) {
			defer wg.Done()
			if err := m.sendAlertToWebhook(alert, webhook); err != nil {
				errChan <- fmt.Errorf("webhook %s: %w", webhook.ID, err)
			}
		}(w)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("send errors: %v", errors)
	}
	return nil
}

// sendAlertToWebhook sends an alert to a specific webhook
func (m *Manager) sendAlertToWebhook(alert *Alert, config *WebhookConfig) error {
	client := m.GetClient(config.ID)

	var payload map[string]interface{}

	switch config.Type {
	case "dingtalk":
		msg := FormatDingTalkAlert(alert)
		payload = convertToMap(msg)
	case "feishu":
		msg := FormatFeishuAlert(alert)
		payload = convertToMap(msg)
	case "wecom":
		msg := FormatWeComAlert(alert)
		payload = convertToMap(msg)
	case "custom":
		payload = m.buildCustomPayload(alert, config)
	default:
		payload = m.buildCustomPayload(alert, config)
	}

	msg := &WebhookMessage{
		Type:    config.Type,
		URL:     config.URL,
		Payload: payload,
	}

	return client.Send(msg)
}

// matchesFilter checks if an alert matches the given filter criteria
func (m *Manager) matchesFilter(alert *Alert, filter *AlertFilter) bool {
	// If no filters specified, match all
	if len(filter.Severity) == 0 && len(filter.Category) == 0 && len(filter.Tags) == 0 {
		return true
	}

	// Check severity filter
	if len(filter.Severity) > 0 {
		found := false
		for _, s := range filter.Severity {
			if equalFold(s, alert.Severity) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check category filter
	if len(filter.Category) > 0 {
		found := false
		for _, c := range filter.Category {
			if equalFold(c, alert.Category) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check tags filter
	if len(filter.Tags) > 0 {
		found := false
		for _, tag := range filter.Tags {
			for _, alertTag := range alert.Tags {
				if equalFold(tag, alertTag) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// buildCustomPayload builds a custom payload from an alert
func (m *Manager) buildCustomPayload(alert *Alert, config *WebhookConfig) map[string]interface{} {
	return map[string]interface{}{
		"id":         alert.ID,
		"severity":   alert.Severity,
		"category":   alert.Category,
		"source_ip":  alert.SourceIP,
		"target_ip":  alert.TargetIP,
		"domain":     alert.Domain,
		"signature":  alert.Signature,
		"detail_url": alert.DetailURL,
		"tags":       alert.Tags,
		"timestamp":  alert.Timestamp.Format(time.RFC3339),
		"metadata":   alert.Metadata,
	}
}

// SendDailyReport sends a daily report to all matching webhooks
func (m *Manager) SendDailyReport(report *DailyReport) error {
	m.mu.RLock()
	var matchingWebhooks []*WebhookConfig
	for _, webhooks := range m.channels {
		for _, w := range webhooks {
			if w.Enabled {
				matchingWebhooks = append(matchingWebhooks, w)
			}
		}
	}
	m.mu.RUnlock()

	if len(matchingWebhooks) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(matchingWebhooks))

	for _, w := range matchingWebhooks {
		wg.Add(1)
		go func(webhook *WebhookConfig) {
			defer wg.Done()
			if err := m.sendReportToWebhook(report, webhook); err != nil {
				errChan <- fmt.Errorf("webhook %s: %w", webhook.ID, err)
			}
		}(w)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("send errors: %v", errors)
	}
	return nil
}

// sendReportToWebhook sends a daily report to a specific webhook
func (m *Manager) sendReportToWebhook(report *DailyReport, config *WebhookConfig) error {
	client := m.GetClient(config.ID)

	var payload map[string]interface{}

	switch config.Type {
	case "dingtalk":
		msg := FormatDingTalkDailyReport(report)
		payload = convertToMap(msg)
	case "feishu":
		msg := FormatFeishuDailyReport(report)
		payload = convertToMap(msg)
	case "wecom":
		msg := FormatWeComDailyReport(report)
		payload = convertToMap(msg)
	default:
		payload = m.buildCustomReportPayload(report)
	}

	msg := &WebhookMessage{
		Type:    config.Type,
		URL:     config.URL,
		Payload: payload,
	}

	return client.Send(msg)
}

// buildCustomReportPayload builds a custom payload from a daily report
func (m *Manager) buildCustomReportPayload(report *DailyReport) map[string]interface{} {
	return map[string]interface{}{
		"date":            report.Date.Format("2006-01-02"),
		"total_alerts":    report.TotalAlerts,
		"critical":        report.Critical,
		"high":            report.High,
		"medium":          report.Medium,
		"low":             report.Low,
		"top_sources":     report.TopSources,
		"top_categories":  report.TopCategories,
		"attack_chains":   report.AttackChains,
	}
}

// convertToMap converts a struct to a map using JSON
func convertToMap(v interface{}) map[string]interface{} {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	return result
}

// equalFold is a simple case-insensitive string comparison
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ac := a[i]
		bc := b[i]
		if ac >= 'A' && ac <= 'Z' {
			ac += 'a' - 'A'
		}
		if bc >= 'A' && bc <= 'Z' {
			bc += 'a' - 'A'
		}
		if ac != bc {
			return false
		}
	}
	return true
}
