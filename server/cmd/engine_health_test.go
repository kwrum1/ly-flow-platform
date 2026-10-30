package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeEVE(t *testing.T, dir string, stats bool) string {
	t.Helper()
	path := filepath.Join(dir, "eve.json")
	content := "{\"timestamp\":\"2026-10-30T11:00:00Z\",\"event_type\":\"dns\"}\n"
	if stats {
		content += "{\"timestamp\":\"2026-10-30T11:00:01Z\",\"event_type\":\"stats\",\"suricata\":{\"version\":\"7.0.11\"}}\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write eve: %v", err)
	}
	return path
}

func TestSuricataVersionFromEVE(t *testing.T) {
	path := writeEVE(t, t.TempDir(), true)
	if got := suricataVersionFromEVE(path); got != "7.0.11" {
		t.Fatalf("version=%q, want 7.0.11", got)
	}
}

func TestSuricataRuntimeStatusFreshEVE(t *testing.T) {
	path := writeEVE(t, t.TempDir(), true)
	t.Setenv("SURICATA_EVE_PATH", path)

	status := suricataRuntimeStatus(time.Now())
	if !asBool(status["installed"]) || !asBool(status["running"]) {
		t.Fatalf("fresh eve must be running: %#v", status)
	}
	if asString(status["version"]) != "7.0.11" {
		t.Fatalf("version=%q", asString(status["version"]))
	}
}

func TestSuricataRuntimeStatusStaleEVE(t *testing.T) {
	path := writeEVE(t, t.TempDir(), false)
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	t.Setenv("SURICATA_EVE_PATH", path)

	status := suricataRuntimeStatus(time.Now())
	if !asBool(status["installed"]) {
		t.Fatalf("eve exists, engine is installed: %#v", status)
	}
	if asBool(status["running"]) {
		t.Fatalf("stale eve must not look running: %#v", status)
	}
}

func TestSuricataRuntimeStatusMissingEVE(t *testing.T) {
	t.Setenv("SURICATA_EVE_PATH", filepath.Join(t.TempDir(), "absent.json"))
	status := suricataRuntimeStatus(time.Now())
	if asBool(status["installed"]) || asBool(status["running"]) {
		t.Fatalf("missing eve must be unavailable: %#v", status)
	}
}
