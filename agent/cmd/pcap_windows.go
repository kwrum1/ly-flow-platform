//go:build windows && amd64

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func (a *Agent) runPCAPPacketCapture() error {
	trafficConfig := a.captureConfigSnapshot()
	captureInterface := strings.TrimSpace(trafficConfig.Interface)
	if captureInterface == "" || strings.EqualFold(captureInterface, "auto") {
		resolved, err := defaultWindowsPCAPInterface(a.cfg.API)
		if err != nil {
			a.markTrafficError(err)
			return err
		}
		captureInterface = resolved
		a.cfgMu.Lock()
		a.cfg.TrafficInterface = resolved
		a.cfgMu.Unlock()
		trafficConfig.Interface = resolved
	}
	if err := validateWindowsPCAPInterface(captureInterface); err != nil {
		a.ensureTrafficQuality().ConfigureInterface(captureInterface, containerBridgePolicy{}, err)
		a.markTrafficError(err)
		return err
	}
	a.ensureTrafficQuality().ConfigureInterface(captureInterface, containerBridgePolicy{}, nil)
	a.markTrafficCaptureStarted(captureInterface)

	handle, err := pcap.OpenLive(captureInterface, 65536, trafficConfig.Promiscuous, time.Second)
	if err != nil {
		a.markTrafficError(err)
		return err
	}
	defer handle.Close()

	if strings.TrimSpace(trafficConfig.BPFFilter) != "" {
		if err := handle.SetBPFFilter(trafficConfig.BPFFilter); err != nil {
			a.markTrafficError(err)
			return fmt.Errorf("set bpf: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	scanDetector := newPortScanDetector()
	packetsSinceStats := uint64(0)
	for {
		select {
		case <-a.ctx.Done():
			a.recordPCAPStats(handle)
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			if !a.captureConfigSnapshot().Enabled {
				continue
			}
			if a.trafficCaptureInterfaceChanged(captureInterface) {
				return fmt.Errorf("capture interface changed from %s to %s", captureInterface, a.captureConfigSnapshot().Interface)
			}
			obs := a.observationFromPacket(packet, len(packet.Data()), "pcap")
			alert, publish := a.processCapturedObservation(scanDetector, obs)
			alertOutcome := trafficPublishAttempt{attempted: alert != nil}
			if alert != nil {
				alertOutcome.err = a.publishAgentStream(a.ctx, "alerts:dpi", alert, "component_alert")
				if alertOutcome.err != nil {
					fmt.Printf("[probe] port scan alert publish failed: %v\n", alertOutcome.err)
				}
			}
			packetsSinceStats++
			if packetsSinceStats >= 1024 {
				a.recordPCAPStats(handle)
				packetsSinceStats = 0
			}
			flowOutcome := trafficPublishAttempt{attempted: publish}
			if publish {
				flowOutcome.err = a.publishTrafficObservation(obs)
				if flowOutcome.err != nil {
					fmt.Printf("[probe] pcap flow publish failed: %v\n", flowOutcome.err)
				}
			}
			a.recordTrafficPublishOutcome(alertOutcome, flowOutcome)
		}
	}
}

func validateWindowsPCAPInterface(name string) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("list pcap interfaces: %w", err)
	}
	for _, device := range devices {
		if device.Name != name {
			continue
		}
		return nil
	}
	return fmt.Errorf("pcap interface %s not found", name)
}

func (a *Agent) recordPCAPStats(handle *pcap.Handle) {
	stats, err := handle.Stats()
	if err != nil {
		a.ensureTrafficQuality().RecordStatsUnavailable()
		return
	}
	a.ensureTrafficQuality().RecordPCAPStats(captureSocketStats{Packets: uint64(stats.PacketsReceived), Drops: uint64(stats.PacketsDropped), InterfaceDrops: uint64(stats.PacketsIfDropped)})
}

func defaultWindowsPCAPInterface(api string) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	preferredIPs := preferredWindowsCaptureIPs(api)
	for _, preferredIP := range preferredIPs {
		for _, device := range devices {
			if strings.TrimSpace(device.Name) == "" || len(device.Addresses) == 0 {
				continue
			}
			for _, address := range device.Addresses {
				if address.IP == nil || address.IP.IsLoopback() {
					continue
				}
				if address.IP.String() == preferredIP {
					return device.Name, nil
				}
			}
		}
	}

	localIPs := localIPv4Set()
	for _, device := range devices {
		if strings.TrimSpace(device.Name) == "" || len(device.Addresses) == 0 {
			continue
		}
		for _, address := range device.Addresses {
			if address.IP == nil || address.IP.IsLoopback() {
				continue
			}
			if localIPs[address.IP.String()] {
				return device.Name, nil
			}
		}
	}
	for _, device := range devices {
		if strings.TrimSpace(device.Name) == "" || len(device.Addresses) == 0 {
			continue
		}
		for _, address := range device.Addresses {
			if address.IP != nil && !address.IP.IsLoopback() && address.IP.To4() != nil {
				return device.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no pcap interface found; install Npcap and verify an active adapter exists")
}

func preferredWindowsCaptureIPs(api string) []string {
	hosts := []string{}
	if host := serverHostFromAPI(api); host != "" {
		hosts = append(hosts, host)
	}
	hosts = append(hosts, "223.5.5.5", "8.8.8.8")
	seen := map[string]bool{}
	result := []string{}
	for _, host := range hosts {
		ip := outboundIPv4ForHost(host)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		result = append(result, ip)
	}
	return result
}

func outboundIPv4ForHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "53"), time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil || addr.IP.To4() == nil || addr.IP.IsLoopback() {
		return ""
	}
	return addr.IP.String()
}

func localIPv4Set() map[string]bool {
	result := map[string]bool{}
	interfaces, _ := net.InterfaceAddrs()
	for _, address := range interfaces {
		ipNet, ok := address.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		result[ipNet.IP.String()] = true
	}
	return result
}
