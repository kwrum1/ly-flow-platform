package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client represents a webhook HTTP client
type Client struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new webhook client with default settings
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// NewClientWithTimeout creates a new webhook client with custom timeout
func NewClientWithTimeout(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
	}
}

// WebhookMessage represents a generic webhook message
type WebhookMessage struct {
	Type    string                 `json:"type"` // dingtalk/wecom/feishu/custom
	URL     string                 `json:"url"`
	Payload map[string]interface{} `json:"payload"`
}

// Send sends a webhook message to the specified URL
func (c *Client) Send(msg *WebhookMessage) error {
	body, err := json.Marshal(msg.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", msg.URL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook error: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// SendWithResponse sends a webhook message and returns the response body
func (c *Client) SendWithResponse(msg *WebhookMessage) ([]byte, error) {
	body, err := json.Marshal(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", msg.URL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return bodyBytes, fmt.Errorf("webhook error: %d", resp.StatusCode)
	}

	return bodyBytes, nil
}

// Alert represents a security alert
type Alert struct {
	ID         string                 `json:"id"`
	Severity   string                 `json:"severity"`   // critical/high/medium/low
	Category   string                 `json:"category"`   // attack type category
	SourceIP   string                 `json:"source_ip"`
	TargetIP   string                 `json:"target_ip"`
	Domain     string                 `json:"domain"`
	Signature  string                 `json:"signature"`
	DetailURL  string                 `json:"detail_url"`
	Tags       []string               `json:"tags"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata"`
}
