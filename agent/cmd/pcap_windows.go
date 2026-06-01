//go:build windows && amd64

package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/redis/go-redis/v9"
)

func (a *Agent) runPCAPPacketCapture() error {
	captureInterface := strings.TrimSpace(a.cfg.TrafficInterface)
	if captureInterface == "" || strings.EqualFold(captureInterface, "auto") {
		resolved, err := defaultWindowsPCAPInterface(a.cfg.API)
		if err != nil {
			a.markTrafficError(err)
			return err
		}
		captureInterface = resolved
		a.cfg.TrafficInterface = resolved
	}
	a.markTrafficCaptureStarted(captureInterface)

	handle, err := pcap.OpenLive(captureInterface, 65536, a.cfg.Promiscuous, time.Second)
	if err != nil {
		a.markTrafficError(err)
		return err
	}
	defer handle.Close()

	if strings.TrimSpace(a.cfg.BPFFilter) != "" {
		if err := handle.SetBPFFilter(a.cfg.BPFFilter); err != nil {
			a.markTrafficError(err)
			return fmt.Errorf("set bpf: %w", err)
		}
	}

	client := redis.NewClient(&redis.Options{Addr: a.cfg.Redis})
	defer client.Close()

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	scanDetector := newPortScanDetector()
	for {
		select {
		case <-a.ctx.Done():
			return nil
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}
			if !a.cfg.TrafficEnabled {
				continue
			}
			obs := a.observationFromPacket(packet, len(packet.Data()), "pcap")
			if obs.Protocol == "" || isContainerBridgeTraffic(obs.SrcIP, obs.DstIP) {
				continue
			}
			a.markTrafficPacket(obs)
			if alert := scanDetector.observe(obs, a); alert != nil {
				if err := publishJSONToStream(a.ctx, client, "alerts:dpi", alert, "component_alert"); err != nil {
					fmt.Printf("[probe] port scan alert publish failed: %v\n", err)
				}
			}
			if err := a.publishTrafficObservation(client, obs); err != nil {
				a.markTrafficError(err)
				fmt.Printf("[probe] pcap flow publish failed: %v\n", err)
			} else {
				a.markTrafficPublish()
			}
		}
	}
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
