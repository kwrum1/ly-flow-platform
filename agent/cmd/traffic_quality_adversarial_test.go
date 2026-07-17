package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrafficPipelineMalformedPacketIncrementsParserDrop(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	agent := NewAgent(&Config{TrafficSampleEveryN: 1})
	agent.clock = clock
	agent.trafficQuality = newTrafficQualityMonitor(clock, captureQualityConfigFrom(agent.cfg))
	agent.trafficQuality.ConfigureInterface("ens33", containerBridgePolicy{}, nil)

	// When
	alert, publish := agent.processCapturedObservation(newPortScanDetector(), trafficObservation{Timestamp: clock.now})

	// Then
	snapshot := agent.trafficQuality.Snapshot(spoolPressure{})
	if alert != nil || publish || snapshot.ParserDrops != 1 || snapshot.Packets != 1 {
		t.Fatalf("malformed packet accounting = alert %#v publish %v snapshot %#v", alert, publish, snapshot)
	}
}

func TestSpoolPressureDirtyTempCountsBytesWithoutPendingRecord(t *testing.T) {
	// Given
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "v2", "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		t.Fatalf("mkdir temp spool: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "interrupted.wal.tmp"), make([]byte, 40), 0o600); err != nil {
		t.Fatalf("write interrupted spool: %v", err)
	}

	// When
	pressure, err := spoolPressureFromDir(dir, 100)

	// Then
	if err != nil || pressure.PendingFiles != 0 || pressure.Bytes != 40 {
		t.Fatalf("dirty spool pressure = %#v error=%v", pressure, err)
	}
}

func TestWaitTrafficRestartCancellationDoesNotHang(t *testing.T) {
	// Given
	agent := NewAgent(&Config{})
	agent.cancel()
	started := time.Now()

	// When
	restarted := agent.waitTrafficRestart()

	// Then
	if restarted || time.Since(started) > 100*time.Millisecond {
		t.Fatalf("cancelled restart wait returned %v after %s", restarted, time.Since(started))
	}
}

func TestCaptureQualityCapabilityNeverClaimsCompleteVisibility(t *testing.T) {
	// Given
	agent := NewAgent(&Config{TrafficEnabled: true, TrafficSampleEveryN: 1, MaxTrafficEventsPerSec: 10})

	// When
	capability := agent.captureQualityCapability()

	// Then
	if capability["visibility_complete"] != false || capability["visibility"] != "partial" || capability["loss_status"] != "unknown" {
		t.Fatalf("misleading visibility capability: %#v", capability)
	}
}
