//go:build windows && amd64

package main

import (
	"fmt"
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
		resolved, err := defaultWindowsPCAPInterface()
		if err != nil {
			return err
		}
		captureInterface = resolved
		a.cfg.TrafficInterface = resolved
	}

	handle, err := pcap.OpenLive(captureInterface, 65536, a.cfg.Promiscuous, time.Second)
	if err != nil {
		return err
	}
	defer handle.Close()

	if strings.TrimSpace(a.cfg.BPFFilter) != "" {
		if err := handle.SetBPFFilter(a.cfg.BPFFilter); err != nil {
			return fmt.Errorf("set bpf: %w", err)
		}
	}

	client := redis.NewClient(&redis.Options{Addr: a.cfg.Redis})
	defer client.Close()

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	scanDetector := newPortScanDetector()
	windowStart := time.Now()
	publishedInWindow := 0
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
			if alert := scanDetector.observe(obs, a); alert != nil {
				if err := publishJSONToStream(a.ctx, client, "alerts:dpi", alert, "component_alert"); err != nil {
					fmt.Printf("[probe] port scan alert publish failed: %v\n", err)
				}
			}
			if time.Since(windowStart) >= time.Second {
				windowStart = time.Now()
				publishedInWindow = 0
			}
			if a.cfg.MaxTrafficEventsPerSec > 0 && publishedInWindow >= a.cfg.MaxTrafficEventsPerSec {
				continue
			}
			if err := a.publishTrafficObservation(client, obs); err != nil {
				fmt.Printf("[probe] pcap flow publish failed: %v\n", err)
			} else {
				publishedInWindow++
			}
		}
	}
}

func defaultWindowsPCAPInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, device := range devices {
		if strings.TrimSpace(device.Name) == "" || len(device.Addresses) == 0 {
			continue
		}
		return device.Name, nil
	}
	return "", fmt.Errorf("no pcap interface found; install Npcap and verify an active adapter exists")
}
