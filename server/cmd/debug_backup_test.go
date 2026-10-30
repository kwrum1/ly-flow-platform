package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckBackupDirectoryEmptyIsHealthy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LYFLOW_BACKUP_DIR", dir)

	status := checkBackupDirectory()
	if status.Status != "ok" {
		t.Fatalf("empty backup dir should be ok, got %q (%s)", status.Status, status.Message)
	}
	if asInt(status.Details["count"]) != 0 {
		t.Fatalf("expected count 0, got %v", status.Details["count"])
	}
	if status.Message != "backup directory ready, no backups yet" {
		t.Fatalf("unexpected message %q", status.Message)
	}
}

func TestCheckBackupDirectoryWithFileIsHealthy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lyflow-20261030.tar.gz"), []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LYFLOW_BACKUP_DIR", dir)

	status := checkBackupDirectory()
	if status.Status != "ok" {
		t.Fatalf("populated backup dir should be ok, got %q", status.Status)
	}
	if asInt(status.Details["count"]) != 1 {
		t.Fatalf("expected count 1, got %v", status.Details["count"])
	}
}

func TestCheckBackupDirectoryMissingIsUnknown(t *testing.T) {
	t.Setenv("LYFLOW_BACKUP_DIR", filepath.Join(t.TempDir(), "missing"))

	status := checkBackupDirectory()
	if status.Status != "unknown" {
		t.Fatalf("missing backup dir should be unknown, got %q", status.Status)
	}
}
