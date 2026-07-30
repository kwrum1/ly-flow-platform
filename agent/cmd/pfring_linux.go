//go:build linux && pfring

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pfring"
)

type pfringReadTimeout struct{ cause error }

func (timeout pfringReadTimeout) Error() string { return timeout.cause.Error() }
func (timeout pfringReadTimeout) Unwrap() error { return timeout.cause }
func (pfringReadTimeout) Timeout() bool         { return true }

type pfringPacketReader struct{ ring *pfring.Ring }

func (reader pfringPacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, captureInfo, err := reader.ring.ZeroCopyReadPacketData()
	if errors.Is(err, pfring.NextNoPacketNonblocking) {
		return data, captureInfo, pfringReadTimeout{cause: err}
	}
	return data, captureInfo, err
}

func pfringAdapterCompiled() bool { return true }

// runPFRingCapture is appliance-only. The normal endpoint agent is built
// without the pfring tag and remains a static Linux 3.10-compatible binary.
func (a *Agent) runPFRingCapture() error {
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

	ring, err := pfring.NewRing(captureInterface, 65536, pfring.FlagPromisc|pfring.FlagLongHeader|pfring.FlagTimestamp)
	if err != nil {
		return err
	}
	defer ring.Close()
	if err := ring.SetApplicationName("ly-local-mirror"); err != nil {
		return err
	}
	if err := ring.SetSocketMode(pfring.ReadOnly); err != nil {
		return err
	}
	if err := ring.SetDirection(pfring.ReceiveOnly); err != nil {
		return err
	}
	if err := ring.SetPollDuration(1000); err != nil {
		return err
	}
	if filter := strings.TrimSpace(trafficConfig.BPFFilter); filter != "" {
		if err := ring.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set PF_RING BPF: %w", err)
		}
	}
	if err := ring.Enable(); err != nil {
		return err
	}

	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}
	scanDetector := newPortScanDetector()
	return runAFPacketCaptureAttempt(a.ctx, pfringPacketReader{ring: ring}, watchdog, captureAttemptCallbacks{
		Ready: func(context.Context) error {
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
				case <-a.restartTraffic:
					return fmt.Errorf("capture configuration changed")
				}
			}
			return nil
		},
		OnTimeout: func() { a.recordPFRingStats(ring) },
		OnPacket: func(data []byte, captureInfo gopacket.CaptureInfo) error {
			packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, decodeOptions)
			observation := a.observationFromPacket(packet, captureInfo.CaptureLength, "pfring")
			alert, publish := a.processCapturedObservation(scanDetector, observation)
			alertOutcome := trafficPublishAttempt{attempted: alert != nil}
			if alert != nil {
				alertOutcome.err = a.publishAgentStream(a.ctx, "alerts:dpi", alert, "component_alert")
			}
			flowOutcome := trafficPublishAttempt{attempted: publish}
			if publish {
				flowOutcome.err = a.publishTrafficObservation(observation)
			}
			a.recordTrafficPublishOutcome(alertOutcome, flowOutcome)
			return nil
		},
	})
}

func (a *Agent) recordPFRingStats(ring *pfring.Ring) {
	stats, err := ring.Stats()
	if err != nil {
		a.ensureTrafficQuality().RecordStatsUnavailable()
		return
	}
	a.ensureTrafficQuality().RecordAFPacketStats(captureSocketStats{Packets: stats.Received, Drops: stats.Dropped})
}
