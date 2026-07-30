package main

import (
	"net"
	"testing"
)

func TestContainerBridgePolicyFiltersOnlyDerivedBridgeNetworks(t *testing.T) {
	// Given
	interfaces := []captureInterfaceMetadata{
		{Name: "ens33", Flags: net.FlagUp, Addresses: mustCIDRs(t, "10.1.18.8/24")},
		{Name: "docker0", Flags: net.FlagUp, Kind: captureInterfaceContainerBridge, Addresses: mustCIDRs(t, "172.19.0.1/16")},
		{Name: "br-stale", Kind: captureInterfaceContainerBridge, Addresses: mustCIDRs(t, "192.168.50.1/24")},
	}

	// When
	policy := deriveContainerBridgePolicy("ens33", interfaces)

	// Then
	if !policy.Contains("172.19.0.5", "10.1.18.8") {
		t.Fatal("derived Docker bridge network was not filtered")
	}
	if policy.Contains("192.168.50.4", "10.1.18.8") {
		t.Fatal("unrelated private traffic was filtered without bridge metadata")
	}
}

func TestContainerBridgePolicyKeepsTrafficWhenSelectedInterfaceIsBridge(t *testing.T) {
	// Given
	interfaces := []captureInterfaceMetadata{{Name: "br-a1", Flags: net.FlagUp, Kind: captureInterfaceContainerBridge, Addresses: mustCIDRs(t, "172.24.0.1/16")}}

	// When
	policy := deriveContainerBridgePolicy("br-a1", interfaces)

	// Then
	if policy.Contains("172.24.0.2", "172.24.0.3") {
		t.Fatal("traffic on the explicitly selected bridge was filtered")
	}
}

func TestValidateCaptureInterfaceAllowsUpLoopbackAndRejectsMissingOrDown(t *testing.T) {
	// Given
	interfaces := []captureInterfaceMetadata{
		{Name: "down0", Addresses: mustCIDRs(t, "192.0.2.1/24")},
		{Name: "empty0", Flags: net.FlagUp},
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addresses: mustCIDRs(t, "127.0.0.1/8")},
		{Name: "ens33", Flags: net.FlagUp, Addresses: mustCIDRs(t, "10.1.18.8/24")},
	}

	// When / Then
	for _, name := range []string{"missing0", "down0"} {
		if err := validateCaptureInterface(name, interfaces); err == nil {
			t.Fatalf("validateCaptureInterface(%q) succeeded", name)
		}
	}
	for _, name := range []string{"empty0", "lo", "ens33"} {
		if err := validateCaptureInterface(name, interfaces); err != nil {
			t.Fatalf("validateCaptureInterface(%s): %v", name, err)
		}
	}
}

func mustCIDRs(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		ip, network, err := net.ParseCIDR(value)
		if err != nil {
			t.Fatalf("parse CIDR %q: %v", value, err)
		}
		network.IP = ip
		result = append(result, network)
	}
	return result
}
