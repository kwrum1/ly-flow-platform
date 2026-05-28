package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RedisAddr      string
	RedisPassword  string
	ConsumerGroup  string
	ConsumerName   string
	InputStreams   []string
	DPIStream      string
	RuntimeStream  string
	RASPStream     string
	LogAuditStream string
	HTTPAddr       string
	BundlePath     string
	BlockByDefault bool
	ReadBlock      time.Duration
}

func Load() Config {
	return Config{
		RedisAddr:      env("REDIS_ADDR", "redis:6379"),
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		ConsumerGroup:  env("SECURITY_ENGINE_GROUP", "security-engine-workers"),
		ConsumerName:   env("SECURITY_ENGINE_NAME", "security-engine-1"),
		InputStreams:   split(env("SECURITY_ENGINE_INPUT_STREAMS", "telemetry:traffic,telemetry:runtime,telemetry:rasp,telemetry:log_audit")),
		DPIStream:      env("ALERTS_DPI_STREAM", "alerts:dpi"),
		RuntimeStream:  env("ALERTS_RUNTIME_STREAM", "alerts:runtime"),
		RASPStream:     env("ALERTS_RASP_STREAM", "alerts:rasp"),
		LogAuditStream: env("ALERTS_LOG_AUDIT_STREAM", "alerts:log_audit"),
		HTTPAddr:       env("SECURITY_ENGINE_HTTP_ADDR", ":8080"),
		BundlePath:     env("SECURITY_ENGINE_BUNDLE", "/app/rules/active-bundle.json"),
		BlockByDefault: boolEnv("RASP_BLOCK_BY_DEFAULT", false),
		ReadBlock:      time.Second,
	}
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func split(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func boolEnv(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}
