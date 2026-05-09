package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for ly-probe
type Config struct {
	RedisAddr      string `yaml:"redis_addr"`
	RedisPassword  string `yaml:"redis_password"`
	RedisStream    string `yaml:"redis_stream"`
	RedisDB        int    `yaml:"redis_db"`
	RedisPoolSize  int    `yaml:"redis_pool_size"`

	CaptureInterface string   `yaml:"capture_interface"`
	CaptureBPFFilter string   `yaml:"capture_bpf_filter"`
	CapturePromisc   bool     `yaml:"capture_promisc"`
	CaptureSnapLen   int      `yaml:"capture_snap_len"`

	SensorID     string `yaml:"sensor_id"`
	BatchSize    int64  `yaml:"batch_size"`
	FlushInterval int   `yaml:"flush_interval"`

	HealthCheckAddr string `yaml:"health_check_addr"`

	LogLevel string `yaml:"log_level"`
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	return &Config{
		RedisAddr:        "localhost:6379",
		RedisPassword:    "",
		RedisStream:      "flows:raw",
		RedisDB:          0,
		RedisPoolSize:    10,

		CaptureInterface: "eth0",
		CaptureBPFFilter: "tcp or udp",
		CapturePromisc:   true,
		CaptureSnapLen:   1600,

		SensorID:      "",
		BatchSize:     100,
		FlushInterval: 1,

		HealthCheckAddr: ":8080",

		LogLevel: "info",
	}
}

// Load loads configuration from file with environment variable overrides
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Load from YAML file
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	// Override with environment variables
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		cfg.RedisAddr = addr
	}
	if password := os.Getenv("REDIS_PASSWORD"); password != "" {
		cfg.RedisPassword = password
	}
	if stream := os.Getenv("REDIS_STREAM"); stream != "" {
		cfg.RedisStream = stream
	}
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		if db, err := strconv.Atoi(dbStr); err == nil {
			cfg.RedisDB = db
		}
	}
	if iface := os.Getenv("CAPTURE_INTERFACE"); iface != "" {
		cfg.CaptureInterface = iface
	}
	if bpf := os.Getenv("CAPTURE_BPF_FILTER"); bpf != "" {
		cfg.CaptureBPFFilter = bpf
	}
	if sensorID := os.Getenv("SENSOR_ID"); sensorID != "" {
		cfg.SensorID = sensorID
	}
	if batchStr := os.Getenv("BATCH_SIZE"); batchStr != "" {
		if batch, err := strconv.ParseInt(batchStr, 10, 64); err == nil {
			cfg.BatchSize = batch
		}
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		cfg.LogLevel = logLevel
	}
	if healthAddr := os.Getenv("HEALTH_CHECK_ADDR"); healthAddr != "" {
		cfg.HealthCheckAddr = healthAddr
	}

	return cfg, nil
}
