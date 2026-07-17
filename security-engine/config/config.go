package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RedisAddr           string
	RedisUsername       string
	RedisPassword       string
	RedisLegacyPassword string
	ConsumerGroup       string
	ConsumerName        string
	InputStreams        []string
	DPIStream           string
	RuntimeStream       string
	RASPStream          string
	LogAuditStream      string
	HTTPAddr            string
	LifecycleManifest   string
	RuleTrustRoot       string
	BundleRoot          string
	ControlToken        string
	ReloadAuditPath     string
	ReadBlock           time.Duration
	ReadCount           int64
	MaxMessageBytes     int
	CPUBudget           time.Duration
	MemoryBudgetBytes   int
	RestartBudget       int
	ControlHealthStream string
}

var ErrLegacyRASPConflict = errors.New("legacy RASP environment conflicts with monitor-first policy")

func Load() Config {
	return Config{
		RedisAddr:           env("REDIS_ADDR", "redis:6379"),
		RedisUsername:       os.Getenv("REDIS_ACL_USERNAME"),
		RedisPassword:       os.Getenv("REDIS_ACL_PASSWORD"),
		RedisLegacyPassword: os.Getenv("REDIS_PASSWORD"),
		ConsumerGroup:       env("SECURITY_ENGINE_GROUP", "security-engine-workers"),
		ConsumerName:        env("SECURITY_ENGINE_NAME", "security-engine-1"),
		InputStreams:        split(env("SECURITY_ENGINE_INPUT_STREAMS", "telemetry:traffic,telemetry:runtime,telemetry:rasp,telemetry:log_audit")),
		DPIStream:           env("ALERTS_DPI_STREAM", "alerts:dpi"),
		RuntimeStream:       env("ALERTS_RUNTIME_STREAM", "alerts:runtime"),
		RASPStream:          env("ALERTS_RASP_STREAM", "alerts:rasp"),
		LogAuditStream:      env("ALERTS_LOG_AUDIT_STREAM", "alerts:log_audit"),
		HTTPAddr:            env("SECURITY_ENGINE_HTTP_ADDR", ":8080"),
		LifecycleManifest:   env("SECURITY_ENGINE_LIFECYCLE_MANIFEST", "/app/rules/security-engine/lifecycle/active-manifest.json"),
		RuleTrustRoot:       env("SECURITY_ENGINE_RULE_TRUST_ROOT", "/var/lib/lyflow/policy/trust/rule-root.pem"),
		BundleRoot:          env("SECURITY_ENGINE_BUNDLE_ROOT", "/app/rules"),
		ControlToken:        firstNonEmpty(os.Getenv("SECURITY_ENGINE_CONTROL_TOKEN"), os.Getenv("REDIS_ACL_PASSWORD"), os.Getenv("REDIS_PASSWORD")),
		ReloadAuditPath:     env("SECURITY_ENGINE_RELOAD_AUDIT_PATH", "/var/lib/lyflow/audit/security-engine-reload.jsonl"),
		ReadBlock:           time.Second,
		ReadCount:           int64(envInt("SECURITY_ENGINE_READ_COUNT", 64, 1, 256)),
		MaxMessageBytes:     envInt("SECURITY_ENGINE_MAX_MESSAGE_BYTES", 1<<20, 1024, 4<<20),
		CPUBudget:           time.Duration(envInt("SECURITY_ENGINE_CPU_BUDGET_MS", 100, 10, 5000)) * time.Millisecond,
		MemoryBudgetBytes:   envInt("SECURITY_ENGINE_MEMORY_BUDGET_BYTES", 16<<20, 1<<20, 128<<20),
		RestartBudget:       envInt("SECURITY_ENGINE_RESTART_BUDGET", 3, 1, 10),
		ControlHealthStream: env("SECURITY_ENGINE_CONTROL_HEALTH_STREAM", "telemetry:runtime"),
	}
}

func envInt(key string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func ValidateLegacyRASPEnvironment() error {
	if raw, exists := os.LookupEnv("RASP_BLOCK_BY_DEFAULT"); exists {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil || value {
			return fmt.Errorf("RASP_BLOCK_BY_DEFAULT=%q: %w", raw, ErrLegacyRASPConflict)
		}
	}
	return nil
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
