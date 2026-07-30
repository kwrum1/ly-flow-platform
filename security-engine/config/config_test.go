package config

import (
	"errors"
	"testing"
	"time"
)

func TestLoad_readsRedisBridgeCredentials(t *testing.T) {
	t.Setenv("REDIS_ACL_USERNAME", "lyflow")
	t.Setenv("REDIS_ACL_PASSWORD", "new-secret")
	t.Setenv("REDIS_PASSWORD", "legacy-secret")

	cfg := Load()

	if cfg.RedisUsername != "lyflow" || cfg.RedisPassword != "new-secret" || cfg.RedisLegacyPassword != "legacy-secret" {
		t.Fatalf("unexpected Redis credentials: username=%q password=%q legacy=%q", cfg.RedisUsername, cfg.RedisPassword, cfg.RedisLegacyPassword)
	}
}

func TestLoad_keepsControlHealthOutsideDetectionInputs(t *testing.T) {
	t.Setenv("SECURITY_ENGINE_CONTROL_HEALTH_STREAM", "")

	cfg := Load()

	if cfg.ControlHealthStream != "control:health" {
		t.Fatalf("control health stream = %q, want control:health", cfg.ControlHealthStream)
	}
	for _, input := range cfg.InputStreams {
		if input == cfg.ControlHealthStream {
			t.Fatalf("control health stream must not be a detection input: %v", cfg.InputStreams)
		}
	}
}

func TestLoad_ignores_legacy_unpinned_bundle_bypass(t *testing.T) {
	// Given
	t.Setenv("SECURITY_ENGINE_BUNDLE", "/tmp/untrusted-bundle.json")
	t.Setenv("SECURITY_ENGINE_LIFECYCLE_MANIFEST", "/trusted/active-manifest.json")

	// When
	cfg := Load()

	// Then
	if cfg.LifecycleManifest != "/trusted/active-manifest.json" {
		t.Fatalf("lifecycle manifest=%q", cfg.LifecycleManifest)
	}
}

func TestValidateLegacyRASPEnvironment_rejects_block_default(t *testing.T) {
	// Given
	t.Setenv("RASP_BLOCK_BY_DEFAULT", "true")

	// When
	err := ValidateLegacyRASPEnvironment()

	// Then
	if !errors.Is(err, ErrLegacyRASPConflict) {
		t.Fatalf("error = %v, want ErrLegacyRASPConflict", err)
	}
}

func TestLoad_runtime_budgets_are_bounded(t *testing.T) {
	// Given
	t.Setenv("SECURITY_ENGINE_READ_COUNT", "9999")
	t.Setenv("SECURITY_ENGINE_MAX_MESSAGE_BYTES", "0")
	t.Setenv("SECURITY_ENGINE_CPU_BUDGET_MS", "99999")
	t.Setenv("SECURITY_ENGINE_MEMORY_BUDGET_BYTES", "0")
	t.Setenv("SECURITY_ENGINE_RESTART_BUDGET", "999")

	// When
	cfg := Load()

	// Then
	if cfg.ReadCount != 64 || cfg.MaxMessageBytes != 1<<20 || cfg.CPUBudget != 100*time.Millisecond || cfg.MemoryBudgetBytes != 16<<20 || cfg.RestartBudget != 3 {
		t.Fatalf("runtime budget fallbacks are not bounded: %+v", cfg)
	}
}
