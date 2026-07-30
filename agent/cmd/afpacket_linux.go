//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

type zeroCopyAFPacketReader struct {
	handle *afpacket.TPacket
}

type afPacketReadTimeout struct {
	cause error
}

func (timeout afPacketReadTimeout) Error() string { return timeout.cause.Error() }
func (timeout afPacketReadTimeout) Unwrap() error { return timeout.cause }
func (afPacketReadTimeout) Timeout() bool         { return true }

func (reader zeroCopyAFPacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, captureInfo, err := reader.handle.ZeroCopyReadPacketData()
	if errors.Is(err, afpacket.ErrTimeout) {
		return data, captureInfo, afPacketReadTimeout{cause: err}
	}
	return data, captureInfo, err
}

func (a *Agent) runAFPacketCapture() error {
	trafficConfig := a.captureConfigSnapshot()
	captureInterface := strings.TrimSpace(trafficConfig.Interface)
	watchdog := localMirrorWatchdog(inactiveLocalMirrorWatchdog{})
	if a.isLocalMirrorMode() {
		watchdog = newLocalMirrorCaptureWatchdog(localMirrorWatchdogPath(), a.clock)
		if err := watchdog.Invalidate(); err != nil {
			return fmt.Errorf("invalidate stale local mirror capture watchdog: %w", err)
		}
	}
	if err := a.prepareTrafficQualityForInterface(captureInterface); err != nil {
		return err
	}
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
	defer a.recordAFPacketSocketStats(handle)

	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	scanDetector := newPortScanDetector()
	packetsSinceStats := uint64(0)
	return runAFPacketCaptureAttempt(a.ctx, zeroCopyAFPacketReader{handle: handle}, watchdog, captureAttemptCallbacks{
		Ready: func(context.Context) error {
			if strings.TrimSpace(trafficConfig.BPFFilter) != "" {
				compiled, err := pcapBPF(layers.LinkTypeEthernet, 65536, trafficConfig.BPFFilter)
				if err != nil {
					return fmt.Errorf("compile bpf: %w", err)
				}
				if err := handle.SetBPF(compiled); err != nil {
					return fmt.Errorf("set bpf: %w", err)
				}
			}
			a.ensureTrafficQuality().ResetAFPacketStats()
			a.markTrafficCaptureStarted(captureInterface)
			return nil
		},
		BeforeRead: func(ctx context.Context) error {
			if a.trafficCaptureInterfaceChanged(captureInterface) {
				return fmt.Errorf("capture interface changed from %s to %s", captureInterface, a.captureConfigSnapshot().Interface)
			}
			for !a.trafficCaptureEnabledOnCurrentInterface(captureInterface) {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(time.Second):
					if a.trafficCaptureInterfaceChanged(captureInterface) {
						return fmt.Errorf("capture interface changed from %s to %s", captureInterface, a.captureConfigSnapshot().Interface)
					}
				}
			}
			return nil
		},
		OnTimeout: func() { a.recordAFPacketSocketStats(handle) },
		OnPacket: func(data []byte, ci gopacket.CaptureInfo) error {
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
			return nil
		},
	})
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
