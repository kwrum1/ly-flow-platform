package main

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

type fixedTrafficClock struct {
	now time.Time
}

func (clock *fixedTrafficClock) Now() time.Time { return clock.now }

func TestTrafficQualityCountsCaptureAndPolicyDrops(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	monitor := newTrafficQualityMonitor(clock, captureQualityConfig{SampleEveryN: 2, RateLimitPerSecond: 1, StaleAfter: time.Minute, MaxClockSkew: 5 * time.Second})
	monitor.ConfigureInterface("ens33", containerBridgePolicy{}, nil)

	// When
	monitor.RecordAFPacketStats(captureSocketStats{Packets: 20, Drops: 3, QueueFreezes: 2})
	monitor.RecordParserDrop()
	monitor.RecordBridgeDrop()
	monitor.RecordSpoolFailure(transport.ErrSpoolFull)
	monitor.RecordPacket(trafficObservation{Timestamp: clock.now})
	monitor.AllowPublish(clock.now)
	monitor.RecordPacket(trafficObservation{Timestamp: clock.now})
	monitor.AllowPublish(clock.now)
	monitor.RecordPacket(trafficObservation{Timestamp: clock.now})
	monitor.AllowPublish(clock.now)

	// Then
	snapshot := monitor.Snapshot(spoolPressure{})
	if snapshot.Packets != 3 || snapshot.KernelPackets != 20 || snapshot.KernelDrops != 3 || snapshot.RingFreezes != 2 {
		t.Fatalf("packet/ring counters = %#v", snapshot)
	}
	if snapshot.ParserDrops != 1 || snapshot.BridgeFiltered != 1 || snapshot.SampledOut != 2 || snapshot.RateLimited != 0 || snapshot.SpoolFull != 1 {
		t.Fatalf("drop counters = %#v", snapshot)
	}
	capability := structToMap(snapshot)
	if snapshot.Status != "degraded" || snapshot.PublishErrors != 1 || capability["publish_status"] != "degraded" || capability["publish_error_reason"] != "spool_full" {
		t.Fatalf("full spool publish health = %#v", capability)
	}
	if snapshot.VisibilityComplete || snapshot.Visibility != "partial" {
		t.Fatalf("visibility claim = complete %v status %q", snapshot.VisibilityComplete, snapshot.Visibility)
	}
}

func TestAFPacketCumulativeSnapshotsRecordEachDeltaOnceAcrossReset(t *testing.T) {
	// Given
	monitor := newTrafficQualityMonitor(&fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}, captureQualityConfig{})
	snapshots := []captureSocketStats{
		{Packets: 100, Drops: 8, QueueFreezes: 2},
		{Packets: 100, Drops: 8, QueueFreezes: 2},
		{Packets: 145, Drops: 11, QueueFreezes: 4},
		{Packets: 7, Drops: 1, QueueFreezes: 1},
	}

	// When
	for _, stats := range snapshots[:3] {
		monitor.RecordAFPacketStats(stats)
	}
	monitor.ResetAFPacketStats()
	monitor.RecordAFPacketStats(snapshots[3])

	// Then
	snapshot := monitor.Snapshot(spoolPressure{})
	if snapshot.KernelPackets != 152 || snapshot.KernelDrops != 12 || snapshot.RingFreezes != 5 {
		t.Fatalf("AF_PACKET deltas counted more than once or inflated on reset: %#v", snapshot)
	}
}

func TestAFPacketCumulativeSnapshotsPreserveUint32WrapDelta(t *testing.T) {
	// Given
	monitor := newTrafficQualityMonitor(&fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}, captureQualityConfig{})

	// When
	monitor.RecordAFPacketStats(captureSocketStats{Packets: math.MaxUint32 - 2, Drops: math.MaxUint32 - 1, QueueFreezes: math.MaxUint32})
	monitor.RecordAFPacketStats(captureSocketStats{Packets: 3, Drops: 2, QueueFreezes: 1})

	// Then
	snapshot := monitor.Snapshot(spoolPressure{})
	if snapshot.KernelPackets != uint64(math.MaxUint32)+4 || snapshot.KernelDrops != uint64(math.MaxUint32)+3 || snapshot.RingFreezes != uint64(math.MaxUint32)+2 {
		t.Fatalf("AF_PACKET uint32 wrap delta was lost or inflated: %#v", snapshot)
	}
}

func TestTrafficPipelineAggregatesScanBeforeRateLimit(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	agent := NewAgent(&Config{TrafficEnabled: true, TrafficInterface: "ens33", TrafficSampleEveryN: 1, MaxTrafficEventsPerSec: 1})
	agent.clock = clock
	agent.localIP = "10.1.18.8"
	agent.trafficQuality = newTrafficQualityMonitor(clock, captureQualityConfigFrom(agent.cfg))
	agent.trafficQuality.ConfigureInterface("ens33", containerBridgePolicy{}, nil)
	detector := newPortScanDetector()
	allowed := 0
	var alert map[string]interface{}

	// When
	for port := uint16(1); port <= 20; port++ {
		observation := trafficObservation{Timestamp: clock.now, Interface: "ens33", SrcIP: "10.1.18.100", DstIP: agent.localIP, SrcPort: 50000 + port, DstPort: port, Protocol: "TCP", TCPSYN: true}
		candidate, publish := agent.processCapturedObservation(detector, observation)
		if candidate != nil {
			alert = candidate
		}
		if publish {
			allowed++
		}
	}

	// Then
	if alert == nil || alert["distinct_dst_ports"] != int64(20) {
		t.Fatalf("scan aggregation lost before limiting: %#v", alert)
	}
	if allowed != 1 || agent.trafficQuality.Snapshot(spoolPressure{}).RateLimited != 19 {
		t.Fatalf("allowed=%d snapshot=%#v", allowed, agent.trafficQuality.Snapshot(spoolPressure{}))
	}
}

func TestTrafficHealthReportsUnknownLossStaleClockAndPartialVisibility(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	monitor := newTrafficQualityMonitor(clock, captureQualityConfig{SampleEveryN: 1, RateLimitPerSecond: 10, StaleAfter: 30 * time.Second, MaxClockSkew: 5 * time.Second})
	monitor.ConfigureInterface("ens33", containerBridgePolicy{}, nil)
	monitor.RecordPacket(trafficObservation{Timestamp: clock.now.Add(-time.Minute)})
	clock.now = clock.now.Add(time.Minute)

	// When
	snapshot := monitor.Snapshot(spoolPressure{})

	// Then
	if snapshot.Status != "degraded" || snapshot.ClockStatus != "skewed" || snapshot.SensorStatus != "stale" {
		t.Fatalf("health = %#v", snapshot)
	}
	if snapshot.LossStatus != "unknown" || snapshot.VisibilityComplete {
		t.Fatalf("loss/visibility overstated: %#v", snapshot)
	}
	if snapshot.ClockSource != "local_wall_clock_no_external_sync" {
		t.Fatalf("clock source overstated: %#v", snapshot)
	}
}

func TestSpoolPressureReportsPendingBytesAndCapacity(t *testing.T) {
	// Given
	dir := t.TempDir()
	pending := filepath.Join(dir, "v2", "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatalf("mkdir pending: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pending, "one.wal"), make([]byte, 80), 0o600); err != nil {
		t.Fatalf("write spool fixture: %v", err)
	}

	// When
	pressure, err := spoolPressureFromDir(dir, 100)

	// Then
	if err != nil {
		t.Fatalf("spoolPressureFromDir: %v", err)
	}
	if pressure.PendingFiles != 1 || pressure.Bytes != 80 || pressure.Percent != 80 || !pressure.Pressured {
		t.Fatalf("spool pressure = %#v", pressure)
	}
}

func TestTrafficHealthMarksInvalidChangedInterfaceUnhealthy(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	monitor := newTrafficQualityMonitor(clock, captureQualityConfig{SampleEveryN: 1, StaleAfter: time.Minute, MaxClockSkew: 5 * time.Second})

	// When
	monitor.ConfigureInterface("missing0", containerBridgePolicy{}, errors.New("capture interface missing0 not found"))
	snapshot := monitor.Snapshot(spoolPressure{})

	// Then
	if snapshot.Status != "unhealthy" || snapshot.InterfaceStatus != "invalid" || snapshot.InterfaceError == "" {
		t.Fatalf("interface health = %#v", snapshot)
	}
}

func TestTrafficHealthRecoversAfterAnyPublishError(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	monitor := newTrafficQualityMonitor(clock, captureQualityConfig{SampleEveryN: 1, StaleAfter: time.Minute, MaxClockSkew: 5 * time.Second})
	monitor.ConfigureInterface("ens33", containerBridgePolicy{}, nil)
	monitor.RecordAFPacketStats(captureSocketStats{})
	monitor.RecordPacket(trafficObservation{Timestamp: clock.now})

	// When
	monitor.RecordSpoolFailure(errors.New("publisher unavailable at tenant-specific endpoint"))
	failed := monitor.Snapshot(spoolPressure{})
	monitor.RecordPublish()
	recovered := monitor.Snapshot(spoolPressure{})

	// Then
	failedCapability := structToMap(failed)
	if failed.Status != "degraded" || failed.PublishErrors != 1 || failedCapability["publish_status"] != "degraded" || failedCapability["publish_error_reason"] != "publish_failed" {
		t.Fatalf("publish outage health = %#v", failedCapability)
	}
	if recovered.Status != "healthy" || recovered.PublishErrors != 1 || recovered.Published != 1 {
		t.Fatalf("publish recovery health = %#v", recovered)
	}
	recoveredCapability := structToMap(recovered)
	if recoveredCapability["publish_status"] != "healthy" {
		t.Fatalf("publish status did not recover: %#v", recoveredCapability)
	}
	if _, exists := recoveredCapability["publish_error_reason"]; exists {
		t.Fatalf("stale publish error reason survived recovery: %#v", recoveredCapability)
	}
}
