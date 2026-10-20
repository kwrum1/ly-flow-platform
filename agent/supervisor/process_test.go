package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewProcessValidation(t *testing.T) {
	if _, err := NewProcess(ProcessConfig{}); err == nil {
		t.Fatal("expected missing name/path error")
	}
	if _, err := NewProcess(ProcessConfig{Name: "x"}); err == nil {
		t.Fatal("expected missing path error")
	}
}

func TestProcessRunsAndLogs(t *testing.T) {
	lines := make(chan string, 4)
	process, err := NewProcess(ProcessConfig{
		Name: "echo", Path: "/bin/sh", Args: []string{"-c", "echo hello-lyflow"},
		Logger: func(line string) { lines <- line },
	})
	if err != nil {
		t.Fatalf("new process: %v", err)
	}
	if err := process.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case line := <-lines:
		if !strings.Contains(line, "hello-lyflow") {
			t.Fatalf("line = %q", line)
		}
	case <-time.After(time.Second):
		t.Fatal("no log line")
	}
}

func TestProcessReportsNonZeroExit(t *testing.T) {
	process, err := NewProcess(ProcessConfig{Name: "exit", Path: "/bin/sh", Args: []string{"-c", "exit 3"}})
	if err != nil {
		t.Fatalf("new process: %v", err)
	}
	if err := process.Start(context.Background()); err == nil {
		t.Fatal("expected non-zero exit error")
	}
}

func TestProcessStopsOnCancel(t *testing.T) {
	process, err := NewProcess(ProcessConfig{Name: "sleep", Path: "/bin/sh", Args: []string{"-c", "sleep 5"}})
	if err != nil {
		t.Fatalf("new process: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- process.Start(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("process did not stop")
	}
}

func TestProcessProbe(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "component.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	process, err := NewProcess(ProcessConfig{Name: "probe", Path: script})
	if err != nil {
		t.Fatalf("new process: %v", err)
	}
	if err := process.Probe(); err != nil {
		t.Fatalf("probe: %v", err)
	}
	missing, _ := NewProcess(ProcessConfig{Name: "missing", Path: filepath.Join(dir, "missing")})
	if err := missing.Probe(); err == nil {
		t.Fatal("expected missing binary error")
	}
	directory, _ := NewProcess(ProcessConfig{Name: "dir", Path: dir})
	if err := directory.Probe(); err == nil {
		t.Fatal("expected directory error")
	}
}
