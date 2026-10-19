package lyprobe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandArgs(t *testing.T) {
	if _, err := CommandArgs(Config{}); !errors.Is(err, ErrInterfaceRequired) {
		t.Fatalf("err = %v", err)
	}
	args, err := CommandArgs(Config{Interface: "ens160", Collector: "10.0.0.10:9995", ExtraArgs: []string{"-e", "0", "-w", "32768"}})
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-i ens160") || !strings.Contains(joined, "-n 10.0.0.10:9995") || !strings.Contains(joined, "-w 32768") {
		t.Fatalf("args = %v", args)
	}
}

func TestNewUsesDefaultPath(t *testing.T) {
	component, err := New(Config{Interface: "ens160"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if component.Name() != "lyprobe" {
		t.Fatalf("name = %q", component.Name())
	}
	if err := component.Probe(); err == nil {
		t.Fatal("expected default path to be absent")
	}
}

func TestNewProbeExplicitBinary(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "lyprobe")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	component, err := New(Config{BinaryPath: binary, Interface: "ens160"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := component.Probe(); err != nil {
		t.Fatalf("probe: %v", err)
	}
}
