package llm

// Config holds configuration for the DeepSeek API client
type Config struct {
	APIKey      string
	Endpoint    string
	Model       string
	MaxTokens   int
	Temperature float64
	Timeout     int // seconds
}

// DefaultConfig returns the default configuration for the DeepSeek client
func DefaultConfig() *Config {
	return &Config{
		Endpoint:    "https://api.deepseek.com/v1/chat/completions",
		Model:       "deepseek-chat",
		MaxTokens:   1000,
		Temperature: 0.7,
		Timeout:     30,
	}
}
