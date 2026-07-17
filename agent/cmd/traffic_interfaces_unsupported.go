//go:build !linux

package main

func captureInterfaceKindForName(string) captureInterfaceKind {
	return captureInterfacePhysical
}
