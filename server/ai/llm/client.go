package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// DeepSeekClient is a client for interacting with the DeepSeek API
type DeepSeekClient struct {
	apiKey     string
	endpoint   string
	model      string
	httpClient *http.Client
}

// ChatRequest represents a request to the chat completions API
type ChatRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

// ChatMessage represents a single message in a chat conversation
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse represents the response from the chat completions API
type ChatResponse struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
}

// Choice represents a single choice in the chat response
type Choice struct {
	Message ChatMessage `json:"message"`
}

// NewClient creates a new DeepSeek API client
func NewClient(apiKey string) *DeepSeekClient {
	return &DeepSeekClient{
		apiKey:   apiKey,
		endpoint: DefaultConfig().Endpoint,
		model:    DefaultConfig().Model,
		httpClient: &http.Client{
			Timeout: time.Duration(DefaultConfig().Timeout) * time.Second,
		},
	}
}

// Chat sends a chat request and returns the assistant's response
func (c *DeepSeekClient) Chat(messages []ChatMessage) (string, error) {
	reqBody := ChatRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   DefaultConfig().MaxTokens,
		Temperature: DefaultConfig().Temperature,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", err
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return "", err
	}

	if len(chatResp.Choices) == 0 {
		return "", err
	}

	return chatResp.Choices[0].Message.Content, nil
}

// ChatWithContext sends a chat request with additional context
func (c *DeepSeekClient) ChatWithContext(prompt, context string) (string, error) {
	messages := []ChatMessage{
		{Role: "system", Content: "你是一个专业的安全分析师。"},
		{Role: "user", Content: context + "\n\n" + prompt},
	}
	return c.Chat(messages)
}
