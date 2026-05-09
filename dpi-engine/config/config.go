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
	}
	Input struct {
		Stream string
		Group  string
		Consumer string
	}
	Output struct {
		Stream string
	}
	Domain struct {
		MiningPath string
		FraudPath  string
		CustomPath string
	}
	Rules struct {
		Path string
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
	cfg.Engine.Workers = getEnvInt("ENGINE_WORKERS", 4)
	cfg.Engine.BlockSeconds = getEnvInt("ENGINE_BLOCK_SECONDS", 5)
	cfg.Engine.BatchSize = int64(getEnvInt("ENGINE_BATCH_SIZE", 100))

	// Input config
	cfg.Input.Stream = getEnv("INPUT_STREAM", "flows:raw")
	cfg.Input.Group = getEnv("INPUT_GROUP", "dpi-workers")
	cfg.Input.Consumer = getEnv("INPUT_CONSUMER", "dpi-engine")

	// Output config
	cfg.Output.Stream = getEnv("OUTPUT_STREAM", "alerts:dpi")

	// Domain lists
	cfg.Domain.MiningPath = getEnv("DOMAIN_MINING_PATH", "rules/domain/mining.txt")
	cfg.Domain.FraudPath = getEnv("DOMAIN_FRAUD_PATH", "rules/domain/fraud.txt")
	cfg.Domain.CustomPath = getEnv("DOMAIN_CUSTOM_PATH", "rules/domain/custom.txt")

	// Suricata rules
	cfg.Rules.Path = getEnv("RULES_PATH", "rules/suricata/et-open.rules")

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