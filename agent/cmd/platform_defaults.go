//go:build !windows

package main

func applyPlatformDefaults(cfg *Config) {}

func applyPlatformTrafficPolicy(cfg *Config) {}

func ensurePlatformInstall() bool { return false }
