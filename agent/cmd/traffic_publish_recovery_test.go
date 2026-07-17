package main

import (
	"errors"
	"testing"
	"time"
)

func TestAFPacketTrafficPublishRecoversAfterAlertOutage(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	agent := NewAgent(&Config{TrafficEnabled: true, TrafficSampleEveryN: 1, MaxTrafficEventsPerSec: 10})
	agent.clock = clock
	agent.trafficQuality = newTrafficQualityMonitor(clock, captureQualityConfigFrom(agent.cfg))
	agent.trafficQuality.ConfigureInterface("ens33", containerBridgePolicy{}, nil)
	agent.markTrafficCaptureStarted("ens33")
	agent.trafficQuality.RecordPacket(trafficObservation{Timestamp: clock.now})
	agent.trafficQuality.RecordAFPacketStats(captureSocketStats{})

	// When
	agent.recordTrafficPublishOutcome(trafficPublishAttempt{attempted: true, err: errors.New("af_packet alert publish failed")}, trafficPublishAttempt{})
	failed := agent.trafficQuality.Snapshot(spoolPressure{})
	agent.recordTrafficPublishOutcome(trafficPublishAttempt{attempted: true}, trafficPublishAttempt{attempted: true})
	recovered := agent.trafficQuality.Snapshot(spoolPressure{})

	// Then
	if failed.Status != "degraded" || failed.PublishErrors != 1 || failed.PublishStatus != "degraded" || failed.PublishErrorReason != "publish_failed" {
		t.Fatalf("AF_PACKET outage health = %#v", failed)
	}
	if recovered.Status != "healthy" || recovered.PublishErrors != 1 || recovered.Published != 1 || recovered.PublishStatus != "healthy" {
		t.Fatalf("AF_PACKET recovery health = %#v", recovered)
	}
	if recovered.PublishErrorReason != "" {
		t.Fatalf("AF_PACKET recovery kept stale publish error reason: %#v", recovered)
	}
}

func TestPCAPTrafficPublishRecoversAfterAlertOutage(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	agent := NewAgent(&Config{TrafficEnabled: true, TrafficSampleEveryN: 1, MaxTrafficEventsPerSec: 10})
	agent.clock = clock
	agent.trafficQuality = newTrafficQualityMonitor(clock, captureQualityConfigFrom(agent.cfg))
	agent.trafficQuality.ConfigureInterface("ens33", containerBridgePolicy{}, nil)
	agent.markTrafficCaptureStarted("ens33")
	agent.trafficQuality.RecordPacket(trafficObservation{Timestamp: clock.now})
	agent.trafficQuality.RecordPCAPStats(captureSocketStats{})

	// When
	agent.recordTrafficPublishOutcome(trafficPublishAttempt{attempted: true, err: errors.New("pcap alert publish failed")}, trafficPublishAttempt{})
	failed := agent.trafficQuality.Snapshot(spoolPressure{})
	agent.recordTrafficPublishOutcome(trafficPublishAttempt{attempted: true}, trafficPublishAttempt{attempted: true})
	recovered := agent.trafficQuality.Snapshot(spoolPressure{})

	// Then
	if failed.Status != "degraded" || failed.PublishErrors != 1 || failed.PublishStatus != "degraded" || failed.PublishErrorReason != "publish_failed" {
		t.Fatalf("PCAP outage health = %#v", failed)
	}
	if recovered.Status != "healthy" || recovered.PublishErrors != 1 || recovered.Published != 1 || recovered.PublishStatus != "healthy" {
		t.Fatalf("PCAP recovery health = %#v", recovered)
	}
	if recovered.PublishErrorReason != "" {
		t.Fatalf("PCAP recovery kept stale publish error reason: %#v", recovered)
	}
}
