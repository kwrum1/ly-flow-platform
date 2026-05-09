package config

import (
	"os"
	"strconv"
)

// Config holds all configuration for ly-server
type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	RedisAddr  string
	ServerPort int
	WSAddr     string
	JWTSecret  string
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		DBHost:     "localhost",
		DBPort:     5432,
		DBUser:     "lyflow",
		DBPassword: "lyflow123",
		DBName:     "lyflow",
		RedisAddr:  "localhost:6379",
		ServerPort: 8080,
		WSAddr:     ":8080",
		JWTSecret:  "ly-flow-secret-key-change-in-production",
	}
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	if v := os.Getenv("DB_HOST"); v != "" {
		cfg.DBHost = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.DBPort = port
		}
	}
	if v := os.Getenv("DB_USER"); v != "" {
		cfg.DBUser = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" {
		cfg.DBPassword = v
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		cfg.DBName = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.RedisAddr = v
	}
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.ServerPort = port
		}
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}

	return cfg
}

// DSN returns the PostgreSQL connection string
func (c *Config) DSN() string {
	return "postgres://" + c.DBUser + ":" + c.DBPassword + "@" + c.DBHost + ":" + strconv.Itoa(c.DBPort) + "/" + c.DBName + "?sslmode=disable"
}