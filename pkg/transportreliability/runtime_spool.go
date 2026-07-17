package transportreliability

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func RuntimeSpoolFromEnv(service string) (*EncryptedSpool, error) {
	encodedKey := strings.TrimSpace(os.Getenv("LYFLOW_TRANSPORT_SPOOL_KEY"))
	key, err := DeriveSpoolKey(service, encodedKey, os.Getenv("REDIS_ACL_PASSWORD"))
	if err != nil {
		if encodedKey == "" && strings.TrimSpace(os.Getenv("REDIS_ACL_PASSWORD")) == "" {
			return nil, nil
		}
		return nil, err
	}
	dir := strings.TrimSpace(os.Getenv("LYFLOW_TRANSPORT_SPOOL_DIR"))
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "lyflow-transport-spool")
	}
	maxBytes, err := parsePositiveInt64("LYFLOW_TRANSPORT_SPOOL_MAX_BYTES", 1<<30)
	if err != nil {
		return nil, err
	}
	maxAgeSeconds, err := parsePositiveInt64("LYFLOW_TRANSPORT_RETRY_HORIZON_SECONDS", int64((7*24*time.Hour)/time.Second))
	if err != nil {
		return nil, err
	}
	return NewEncryptedSpool(SpoolConfig{
		Dir: filepath.Join(dir, safeName(service)), Key: key,
		MaxBytes: maxBytes, MaxAge: time.Duration(maxAgeSeconds) * time.Second,
	})
}

func DeriveSpoolKey(service, encodedKey, fallbackSecret string) ([]byte, error) {
	if strings.TrimSpace(encodedKey) != "" {
		return decodeSpoolKey(strings.TrimSpace(encodedKey))
	}
	if strings.TrimSpace(fallbackSecret) == "" {
		return nil, fmt.Errorf("encrypted spool key material is required")
	}
	sum := sha256.Sum256([]byte("lyflow-transport-spool-v1\x00" + service + "\x00" + fallbackSecret))
	return sum[:], nil
}

func decodeSpoolKey(encoded string) ([]byte, error) {
	if decoded, err := hex.DecodeString(encoded); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("LYFLOW_TRANSPORT_SPOOL_KEY must encode exactly 32 bytes")
	}
	return decoded, nil
}

func parsePositiveInt64(name string, fallback int64) (int64, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}
