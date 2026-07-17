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
	"golang.org/x/net/bpf"
)

func (a *Agent) runAFPacketCapture() error {
	trafficConfig := a.captureConfigSnapshot()
	captureInterface := strings.TrimSpace(trafficConfig.Interface)
	if err := a.prepareTrafficQualityForInterface(captureInterface); err != nil {
		return err
	}
	a.markTrafficCaptureStarted(captureInterface)
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
	a.ensureTrafficQuality().ResetAFPacketStats()

	if strings.TrimSpace(trafficConfig.BPFFilter) != "" {
		bpf, err := pcapBPF(layers.LinkTypeEthernet, 65536, trafficConfig.BPFFilter)
		if err != nil {
			return fmt.Errorf("compile bpf: %w", err)
		}
		if err := handle.SetBPF(bpf); err != nil {
			return fmt.Errorf("set bpf: %w", err)
		}
	}

	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	scanDetector := newPortScanDetector()
	packetsSinceStats := uint64(0)
	for {
		select {
		case <-a.ctx.Done():
			a.recordAFPacketSocketStats(handle)
			return nil
		default:
		}
		if a.trafficCaptureInterfaceChanged(captureInterface) {
			return fmt.Errorf("capture interface changed from %s to %s", captureInterface, a.captureConfigSnapshot().Interface)
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
				a.recordAFPacketSocketStats(handle)
				continue
			}
			return err
		}
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, decodeOptions)
		obs := a.observationFromPacket(packet, ci.CaptureLength, "af_packet")
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
			a.recordAFPacketSocketStats(handle)
			packetsSinceStats = 0
		}
		flowOutcome := trafficPublishAttempt{attempted: publish}
		if publish {
			flowOutcome.err = a.publishTrafficObservation(obs)
			if flowOutcome.err != nil {
				fmt.Printf("[probe] flow publish failed: %v\n", flowOutcome.err)
			}
		}
		a.recordTrafficPublishOutcome(alertOutcome, flowOutcome)
	}
}

func (a *Agent) recordAFPacketSocketStats(handle *afpacket.TPacket) {
	stats, statsV3, err := handle.SocketStats()
	if err != nil {
		a.ensureTrafficQuality().RecordStatsUnavailable()
		return
	}
	a.ensureTrafficQuality().RecordAFPacketStats(captureSocketStats{
		Packets:      uint64(stats.Packets()) + uint64(statsV3.Packets()),
		Drops:        uint64(stats.Drops()) + uint64(statsV3.Drops()),
		QueueFreezes: uint64(statsV3.QueueFreezes()),
	})
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
