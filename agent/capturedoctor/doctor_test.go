package capturedoctor

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeProbe struct {
	iface      InterfaceInfo
	ifaceErr   error
	softnet    SoftnetInfo
	softnetErr error
	ethtool    EthtoolInfo
	ethtoolErr error
	process    ProcessInfo
	processErr error
	pfring     bool
	now        time.Time
}

func (f *fakeProbe) Interface(string) (InterfaceInfo, error) { return f.iface, f.ifaceErr }
func (f *fakeProbe) Softnet() (SoftnetInfo, error)           { return f.softnet, f.softnetErr }
func (f *fakeProbe) Ethtool(string) (EthtoolInfo, error)     { return f.ethtool, f.ethtoolErr }
func (f *fakeProbe) Process(string, string) (ProcessInfo, error) {
	return f.process, f.processErr
}
func (f *fakeProbe) PFRing() bool   { return f.pfring }
func (f *fakeProbe) Now() time.Time { return f.now }

func healthyProbe() *fakeProbe {
	return &fakeProbe{
		iface:   InterfaceInfo{Exists: true, Up: true, MTU: 1500, RXPackets: 1000},
		softnet: SoftnetInfo{Dropped: 10},
		ethtool: EthtoolInfo{Available: true, RingRX: 4096},
		process: ProcessInfo{Running: true, PID: 42, Name: "lyprobe", RSSKB: 1024},
		pfring:  true,
		now:     time.Unix(1000, 0),
	}
}

func newTestDoctor(probe *fakeProbe) *Doctor {
	return New(Config{
		Interface:    "ens160",
		ProcessName:  "lyprobe",
		DropWarnPct:  1,
		DropCritPct:  5,
		RingMin:      2048,
		RestartAfter: 3,
		Probe:        probe,
		Logger:       log.New(io.Discard, "", 0),
	})
}

func TestHealthySnapshot(t *testing.T) {
	probe := healthyProbe()
	doctor := newTestDoctor(probe)
	snapshot := doctor.Check(context.Background())
	if snapshot.Status != StatusOK {
		t.Fatalf("status = %s, issues=%+v", snapshot.Status, snapshot.Issues)
	}
	if !snapshot.Metrics.InterfaceUp || snapshot.Metrics.RingRX != 4096 || !snapshot.Process.Running {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestDropRateWarningAndCritical(t *testing.T) {
	probe := healthyProbe()
	doctor := newTestDoctor(probe)
	doctor.Check(context.Background())

	probe.now = probe.now.Add(time.Second)
	probe.iface.RXPackets += 1000
	probe.iface.RXDropped += 20
	snapshot := doctor.Check(context.Background())
	if snapshot.Status != StatusWarn {
		t.Fatalf("warning status = %s, drop=%.2f issues=%+v", snapshot.Status, snapshot.Metrics.DropPct, snapshot.Issues)
	}

	probe.now = probe.now.Add(time.Second)
	probe.iface.RXPackets += 1000
	probe.iface.RXDropped += 100
	snapshot = doctor.Check(context.Background())
	if snapshot.Status != StatusCritical {
		t.Fatalf("critical status = %s, drop=%.2f issues=%+v", snapshot.Status, snapshot.Metrics.DropPct, snapshot.Issues)
	}
	if !hasIssue(snapshot, "drop_critical") {
		t.Fatalf("missing drop_critical: %+v", snapshot.Issues)
	}
}

func TestExistingDropsDoNotAlarmUntilTheyIncrease(t *testing.T) {
	probe := healthyProbe()
	probe.iface.RXPackets = 100000
	probe.iface.RXDropped = 5000
	doctor := newTestDoctor(probe)
	first := doctor.Check(context.Background())
	if first.Status != StatusOK {
		t.Fatalf("baseline should be ok: %+v", first)
	}
	probe.now = probe.now.Add(time.Second)
	probe.iface.RXPackets += 1000
	second := doctor.Check(context.Background())
	if second.Metrics.RXDroppedDelta != 0 || second.Status != StatusOK {
		t.Fatalf("unexpected second check: %+v", second)
	}
}

func TestInterfaceDownAndProcessMissing(t *testing.T) {
	probe := healthyProbe()
	probe.iface.Up = false
	probe.process.Running = false
	doctor := newTestDoctor(probe)
	snapshot := doctor.Check(context.Background())
	if snapshot.Status != StatusCritical {
		t.Fatalf("status = %s", snapshot.Status)
	}
	if !hasIssue(snapshot, "interface_down") || !hasIssue(snapshot, "process_missing") {
		t.Fatalf("issues = %+v", snapshot.Issues)
	}
}

func TestOffloadRingAndPFRingWarnings(t *testing.T) {
	probe := healthyProbe()
	probe.ethtool.RingRX = 1024
	probe.ethtool.GRO = true
	probe.ethtool.GSO = true
	probe.pfring = false
	doctor := newTestDoctor(probe)
	snapshot := doctor.Check(context.Background())
	if snapshot.Status != StatusWarn {
		t.Fatalf("status = %s", snapshot.Status)
	}
	for _, code := range []string{"ring_small", "gro_enabled", "gso_enabled", "pf_ring_unavailable"} {
		if !hasIssue(snapshot, code) {
			t.Fatalf("missing %s: %+v", code, snapshot.Issues)
		}
	}
}

func TestRestartRequiresExplicitCommandAndThreshold(t *testing.T) {
	probe := healthyProbe()
	probe.iface.Up = false
	restarts := 0
	doctor := New(Config{
		Interface:       "ens160",
		ProcessName:     "lyprobe",
		DropWarnPct:     1,
		DropCritPct:     5,
		RingMin:         2048,
		RestartAfter:    2,
		RestartCooldown: time.Minute,
		RestartFunc: func(context.Context) error {
			restarts++
			return nil
		},
		Probe:  probe,
		Logger: log.New(io.Discard, "", 0),
	})
	first := doctor.Check(context.Background())
	if first.Restarted || restarts != 0 {
		t.Fatalf("restarted before threshold: %+v restarts=%d", first, restarts)
	}
	probe.now = probe.now.Add(time.Second)
	second := doctor.Check(context.Background())
	if !second.Restarted || restarts != 1 {
		t.Fatalf("restart threshold not honored: %+v restarts=%d", second, restarts)
	}
	if !hasIssue(second, "restart") {
		t.Fatalf("restart was not reported: %+v", second.Issues)
	}
	probe.now = probe.now.Add(time.Second)
	third := doctor.Check(context.Background())
	if third.Restarted || restarts != 1 {
		t.Fatalf("restart cooldown not honored: %+v restarts=%d", third, restarts)
	}
}

func TestCriticalWithoutRestartCommandIsNotSilent(t *testing.T) {
	probe := healthyProbe()
	probe.iface.Up = false
	doctor := newTestDoctor(probe)
	snapshot := doctor.Check(context.Background())
	if snapshot.Status != StatusCritical || snapshot.Restarted {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if !hasIssue(snapshot, "interface_down") {
		t.Fatalf("issues = %+v", snapshot.Issues)
	}
}

func TestWriteSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture-doctor.json")
	snapshot := Snapshot{Timestamp: time.Unix(1, 0), Interface: "ens160", Status: StatusWarn, Issues: []Issue{{Code: "x", Severity: StatusWarn, Message: "y"}}}
	if err := WriteSnapshot(path, snapshot); err != nil {
		t.Fatalf("write: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Status != StatusWarn || decoded.Interface != "ens160" {
		t.Fatalf("decoded = %+v", decoded)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temp files left: %+v", entries)
	}
}

func TestParseNetDevAndSoftnet(t *testing.T) {
	payload := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
ens160: 12345 100 2 3 4 5 6 7 8 9 10 11 12 13 14 15
`
	info, ok := parseNetDev(payload, "ens160")
	if !ok || info.RXPackets != 100 || info.RXErrors != 2 || info.RXDropped != 3 || info.RXFIFO != 4 {
		t.Fatalf("parseNetDev = %+v ok=%v", info, ok)
	}
	soft, err := parseSoftnet("00000001 0000000a 00000002 00000000\n00000001 00000005 00000001 00000000\n")
	if err != nil || soft.Dropped != 15 || soft.Squeezed != 3 {
		t.Fatalf("parseSoftnet = %+v err=%v", soft, err)
	}
}

func TestParseEthtoolOutputs(t *testing.T) {
	ring := "Ring parameters for ens160:\nCurrent hardware settings:\nRX: 1024\nTX: 1024\n"
	if value := parseRingRX(ring); value != 1024 {
		t.Fatalf("ring = %d", value)
	}
	features := "Features for ens160:\n generic-receive-offload: on\n tx-generic-segmentation: off\n"
	if !featureOn(features, "generic-receive-offload") || featureOn(features, "tx-generic-segmentation") {
		t.Fatalf("feature parse failed")
	}
	stats := parseEthtoolStats("rx_missed_errors: 7\nrx_no_buffer_count: 3\n")
	if stats["rx_missed_errors"] != 7 || stats["rx_no_buffer_count"] != 3 {
		t.Fatalf("stats = %+v", stats)
	}
}

func hasIssue(snapshot Snapshot, code string) bool {
	for _, issue := range snapshot.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
