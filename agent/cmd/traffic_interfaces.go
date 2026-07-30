package main

import (
	"fmt"
	"net"
	"strings"
)

type captureInterfaceKind uint8

const (
	captureInterfacePhysical captureInterfaceKind = iota
	captureInterfaceContainerBridge
)

type captureInterfaceMetadata struct {
	Name      string
	Flags     net.Flags
	Kind      captureInterfaceKind
	Addresses []*net.IPNet
}

type containerBridgePolicy struct {
	networks []*net.IPNet
}

func loadCaptureInterfaces() ([]captureInterfaceMetadata, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list capture interfaces: %w", err)
	}
	result := make([]captureInterfaceMetadata, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for interface %s: %w", iface.Name, err)
		}
		metadata := captureInterfaceMetadata{Name: iface.Name, Flags: iface.Flags, Kind: captureInterfaceKindForName(iface.Name)}
		for _, address := range addresses {
			ip, network, err := net.ParseCIDR(address.String())
			if err != nil || ip == nil || network == nil {
				continue
			}
			network.IP = ip.Mask(network.Mask)
			metadata.Addresses = append(metadata.Addresses, network)
		}
		result = append(result, metadata)
	}
	return result, nil
}

func validateCaptureInterface(name string, interfaces []captureInterfaceMetadata) error {
	selected := strings.TrimSpace(name)
	if selected == "" || strings.EqualFold(selected, "auto") {
		return fmt.Errorf("capture interface must resolve to an explicit interface")
	}
	for _, iface := range interfaces {
		if iface.Name != selected {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			return fmt.Errorf("capture interface %s is down", selected)
		}
		return nil
	}
	return fmt.Errorf("capture interface %s not found", selected)
}

func deriveContainerBridgePolicy(selected string, interfaces []captureInterfaceMetadata) containerBridgePolicy {
	policy := containerBridgePolicy{}
	for _, iface := range interfaces {
		if iface.Name == selected || iface.Kind != captureInterfaceContainerBridge || iface.Flags&net.FlagUp == 0 {
			continue
		}
		policy.networks = append(policy.networks, iface.Addresses...)
	}
	return policy
}

func (policy containerBridgePolicy) Contains(srcIP, dstIP string) bool {
	for _, raw := range []string{srcIP, dstIP} {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		for _, network := range policy.networks {
			if network != nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}
