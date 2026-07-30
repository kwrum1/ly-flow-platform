package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const localMirrorHealthcheckHelperEnv = "LYFLOW_LOCAL_MIRROR_HEALTHCHECK_HELPER"

func TestHealthcheckLocalMirrorBypassesPoisonedNormalStartup(t *testing.T) {
	tests := []struct {
		name    string
		healthy bool
	}{
		{name: "fresh watchdog exits successfully", healthy: true},
		{name: "missing watchdog exits with bounded diagnostic", healthy: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			watchdogPath := filepath.Join(t.TempDir(), "capture-watchdog")
			if test.healthy {
				if err := os.WriteFile(watchdogPath, []byte("ready\n"), 0o600); err != nil {
					t.Fatalf("write watchdog: %v", err)
				}
			}
			secret := "poison-secret-must-not-appear"
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHealthcheckLocalMirrorSubprocessHelper$")
			command.Env = append(os.Environ(),
				localMirrorHealthcheckHelperEnv+"=1",
				"LOCAL_MIRROR_WATCHDOG_PATH="+watchdogPath,
				"CONFIG_FILE=/missing/"+secret,
				"AGENT_BINARY_DIGEST=/missing/"+secret,
				"AGENT_BINARY_ROOT=/missing/"+secret,
				"AGENT_REQUIRE_BINARY_INTEGRITY=true",
			)

			output, err := command.CombinedOutput()

			if test.healthy && err != nil {
				t.Fatalf("healthy subprocess: %v: %s", err, output)
			}
			if !test.healthy {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					t.Fatalf("unhealthy subprocess error = %v, output = %q", err, output)
				}
			}
			if len(output) > 256 {
				t.Fatalf("healthcheck diagnostic is unbounded: %d bytes", len(output))
			}
			if strings.Contains(string(output), secret) {
				t.Fatal("healthcheck diagnostic disclosed poisoned startup data")
			}
		})
	}
}

func TestHealthcheckLocalMirrorSubprocessHelper(t *testing.T) {
	if os.Getenv(localMirrorHealthcheckHelperEnv) != "1" {
		return
	}
	os.Args = []string{os.Args[0], "healthcheck", "local-mirror"}
	main()
}
