package redisconfig

import "testing"

func TestOptions_usesACLcredentials_whenConfigured(t *testing.T) {
	t.Setenv("REDIS_ACL_USERNAME", "lyflow")
	t.Setenv("REDIS_ACL_PASSWORD", "new-secret")
	t.Setenv("REDIS_PASSWORD", "legacy-secret")

	options := Options("redis:6379", 1)

	if options.Username != "lyflow" || options.Password != "new-secret" {
		t.Fatalf("expected ACL credentials, got username=%q password=%q", options.Username, options.Password)
	}
	if options.Addr != "redis:6379" || options.DB != 1 {
		t.Fatalf("unexpected connection target: addr=%q db=%d", options.Addr, options.DB)
	}
}

func TestOptions_usesLegacyPassword_whenACLcredentialsAreIncomplete(t *testing.T) {
	t.Setenv("REDIS_ACL_USERNAME", "")
	t.Setenv("REDIS_ACL_PASSWORD", "")
	t.Setenv("REDIS_PASSWORD", "legacy-secret")

	options := Options("redis:6379", 0)

	if options.Username != "" || options.Password != "legacy-secret" {
		t.Fatalf("expected legacy credentials, got username=%q password=%q", options.Username, options.Password)
	}
}
