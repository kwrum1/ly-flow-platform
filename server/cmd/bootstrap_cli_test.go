package main

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func TestParseBootstrapTokenCommandDefaultsTo15Minutes(t *testing.T) {
	// Given
	args := []string{"bootstrap-token", "create"}

	// When
	command, handled, err := parseBootstrapTokenCommand(args)

	// Then
	if err != nil || !handled || command.Mode != auth.BootstrapCreate || command.TTL != 15*time.Minute {
		t.Fatalf("command=%#v handled=%v error=%v", command, handled, err)
	}
}

func TestParseBootstrapTokenCommandRejectsMalformedInput(t *testing.T) {
	for _, args := range [][]string{
		{"bootstrap-token", "create", "--ttl", "garbage"},
		{"bootstrap-token", "recover", "--ttl", "16m"},
		{"bootstrap-token", "unknown"},
	} {
		_, handled, err := parseBootstrapTokenCommand(args)
		if !handled || err == nil {
			t.Fatalf("args=%v handled=%v error=%v", args, handled, err)
		}
	}
}

func TestAcquireServiceLockAllowsOnlyOneOwner(t *testing.T) {
	// Given
	path := t.TempDir() + "/ly-server.lock"
	first, err := acquireServiceLock(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer first.Close()

	// When
	second, err := acquireServiceLock(path)

	// Then
	if err == nil {
		second.Close()
		t.Fatal("second process lock unexpectedly succeeded")
	}
}
