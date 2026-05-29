//go:build linux

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/bpf"
)

func (a *Agent) runAFPacketCapture() error {
	captureInterface := a.cfg.TrafficInterface
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(captureInterface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(16),
		afpacket.OptPollTimeout(time.Second),
	)
	if err != nil {
		return err
	}
	defer handle.Close()

	if strings.TrimSpace(a.cfg.BPFFilter) != "" {
		bpf, err := pcapBPF(layers.LinkTypeEthernet, 65536, a.cfg.BPFFilter)
		if err != nil {
			return fmt.Errorf("compile bpf: %w", err)
		}
		if err := handle.SetBPF(bpf); err != nil {
			return fmt.Errorf("set bpf: %w", err)
		}
	}

	client := redis.NewClient(&redis.Options{Addr: a.cfg.Redis})
	defer client.Close()

	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	scanDetector := newPortScanDetector()
	windowStart := time.Now()
	publishedInWindow := 0
	for {
		select {
		case <-a.ctx.Done():
			return nil
		default:
		}
		if !a.trafficCaptureEnabledOnCurrentInterface(captureInterface) {
			select {
			case <-a.ctx.Done():
				return nil
			case <-time.After(time.Second):
				continue
			}
		}

		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				continue
			}
			return err
		}
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, decodeOptions)
		obs := a.observationFromPacket(packet, ci.CaptureLength, "af_packet")
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
			fmt.Printf("[probe] flow publish failed: %v\n", err)
		} else {
			publishedInWindow++
		}
	}
}

func pcapBPF(linkType layers.LinkType, snapLen int, filter string) ([]bpf.RawInstruction, error) {
	instructions, err := pcap.CompileBPFFilter(linkType, snapLen, filter)
	if err != nil {
		return nil, err
	}
	raw := make([]bpf.RawInstruction, 0, len(instructions))
	for _, ins := range instructions {
		raw = append(raw, bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K})
	}
	return raw, nil
}
