//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
)

func captureInterfaceKindForName(name string) captureInterfaceKind {
	lower := strings.ToLower(strings.TrimSpace(name))
	containerName := lower == "docker0" || lower == "cni0" || lower == "podman0" || strings.HasPrefix(lower, "br-") || strings.HasPrefix(lower, "cni-") || strings.HasPrefix(lower, "weave") || strings.HasPrefix(lower, "flannel")
	if !containerName {
		return captureInterfacePhysical
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "bridge")); err == nil {
		return captureInterfaceContainerBridge
	}
	return captureInterfacePhysical
}
