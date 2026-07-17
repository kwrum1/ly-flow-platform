package main

import "testing"

func TestRedisOptions_usesACLcredentials_whenConfigured(t *testing.T) {
	cfg := &Config{Redis: "redis:6379", RedisUsername: "lyflow", RedisPassword: "new-secret", RedisLegacyPassword: "legacy-secret"}

	options := redisOptions(cfg)

	if options.Username != "lyflow" || options.Password != "new-secret" {
		t.Fatalf("expected ACL credentials, got username=%q password=%q", options.Username, options.Password)
	}
}

func TestRedisOptions_usesLegacyPassword_whenACLcredentialsAreIncomplete(t *testing.T) {
	cfg := &Config{Redis: "redis:6379", RedisLegacyPassword: "legacy-secret"}

	options := redisOptions(cfg)

	if options.Username != "" || options.Password != "legacy-secret" {
		t.Fatalf("expected legacy credentials, got username=%q password=%q", options.Username, options.Password)
	}
}
