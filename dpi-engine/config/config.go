package config

import (
	"os"
	"strconv"
)

// Config holds all configuration for the DPI engine
type Config struct {
	Redis struct {
		Addr     string
		Password string
		DB       int
	}
	Engine struct {
		Workers      int
		BlockSeconds int
		BatchSize    int64
		EnableJA3    bool
	}
	Input struct {
		Stream   string
		Group    string
		Consumer string
	}
	Output struct {
		Stream         string
		SemanticStream string
		SessionStream  string
	}
	Domain struct {
		MiningPath string
		FraudPath  string
		CustomPath string
	}
	Rules struct {
		Path        string
		DatabaseDir string
	}
	HTTP struct {
		Addr string
	}
}

// Load loads configuration from environment variables
func Load() *Config {
	cfg := &Config{}

	// Redis config
	cfg.Redis.Addr = getEnv("REDIS_ADDR", "localhost:6379")
	cfg.Redis.Password = getEnv("REDIS_PASSWORD", "")
	cfg.Redis.DB = getEnvInt("REDIS_DB", 0)

	// Engine config
	cfg.Engine.Workers = getEnvIntAny([]string{"ENGINE_WORKERS", "WORKERS"}, 4)
	cfg.Engine.BlockSeconds = getEnvInt("ENGINE_BLOCK_SECONDS", 5)
	cfg.Engine.BatchSize = int64(getEnvInt("ENGINE_BATCH_SIZE", 100))
	cfg.Engine.EnableJA3 = getEnvBoolAny([]string{"ENGINE_ENABLE_JA3", "ENABLE_JA3"}, false)

	// Input config
	cfg.Input.Stream = getEnvAny([]string{"INPUT_STREAM", "REDIS_STREAM_IN"}, "flows:raw")
	cfg.Input.Group = getEnvAny([]string{"INPUT_GROUP", "CONSUMER_GROUP"}, "dpi-workers")
	cfg.Input.Consumer = getEnvAny([]string{"INPUT_CONSUMER", "CONSUMER_NAME"}, "dpi-engine")

	// Output config
	cfg.Output.Stream = getEnvAny([]string{"OUTPUT_STREAM", "REDIS_STREAM_OUT"}, "alerts:dpi")
	cfg.Output.SemanticStream = getEnvAny([]string{"SEMANTIC_STREAM", "OUTPUT_SEMANTIC_STREAM", "REDIS_STREAM_SEMANTIC"}, "flows:semantic")
	cfg.Output.SessionStream = getEnvAny([]string{"SESSION_STREAM", "OUTPUT_SESSION_STREAM", "REDIS_STREAM_SESSION"}, "sessions:semantic")

	// Domain lists
	cfg.Domain.MiningPath = getEnvAny([]string{"DOMAIN_MINING_PATH", "DOMAIN_MINING"}, "/etc/ly/rules/domain/mining.txt")
	cfg.Domain.FraudPath = getEnvAny([]string{"DOMAIN_FRAUD_PATH", "DOMAIN_FRAUD"}, "/etc/ly/rules/domain/fraud.txt")
	cfg.Domain.CustomPath = getEnvAny([]string{"DOMAIN_CUSTOM_PATH", "DOMAIN_CUSTOM"}, "/etc/ly/rules/domain/custom.txt")

	// Suricata rules
	cfg.Rules.Path = getEnvAny([]string{"RULES_PATH", "RULES_FILE"}, "rules/suricata/et-open.rules")
	cfg.Rules.DatabaseDir = getEnv("DATABASE_RULES_PATH", "rules/database")

	// HTTP server
	cfg.HTTP.Addr = getEnv("HTTP_ADDR", ":8080")

	return cfg
}

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvAny(keys []string, defaultValue string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return defaultValue
}

func getEnvIntAny(keys []string, defaultValue int) int {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return defaultValue
}

func getEnvBoolAny(keys []string, defaultValue bool) bool {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				return b
			}
		}
	}
	return defaultValue
}
