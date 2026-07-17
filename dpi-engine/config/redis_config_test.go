package config

import "testing"

func TestLoad_readsRedisBridgeCredentials(t *testing.T) {
	t.Setenv("REDIS_ACL_USERNAME", "lyflow")
	t.Setenv("REDIS_ACL_PASSWORD", "new-secret")
	t.Setenv("REDIS_PASSWORD", "legacy-secret")

	cfg := Load()

	if cfg.Redis.Username != "lyflow" || cfg.Redis.Password != "new-secret" || cfg.Redis.LegacyPassword != "legacy-secret" {
		t.Fatalf("unexpected Redis credentials: username=%q password=%q legacy=%q", cfg.Redis.Username, cfg.Redis.Password, cfg.Redis.LegacyPassword)
	}
}
