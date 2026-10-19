package capturedoctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	StatusOK       = "ok"
	StatusWarn     = "warn"
	StatusCritical = "critical"
)

func (d *Doctor) Check(ctx context.Context) Snapshot {
	if ctx == nil {
		ctx = context.Background()
	}
	now := d.probe.Now()
	snapshot := Snapshot{
		Timestamp: now,
		Interface: d.cfg.Interface,
		Status:    StatusOK,
		Issues:    []Issue{},
	}
	d.cfg.Logger.Printf("capture doctor: checking interface=%s", d.cfg.Interface)

	iface, err := d.probe.Interface(d.cfg.Interface)
	if err != nil {
		d.haveBaseline = false
		addIssue(&snapshot, "interface_error", StatusCritical, "interface probe failed: "+err.Error())
	} else if !iface.Exists {
		d.haveBaseline = false
		addIssue(&snapshot, "interface_missing", StatusCritical, "interface does not exist")
	} else {
		snapshot.Metrics.InterfaceUp = iface.Up
		snapshot.Metrics.MTU = iface.MTU
		snapshot.Metrics.RXPackets = iface.RXPackets
		snapshot.Metrics.RXDropped = iface.RXDropped
		snapshot.Metrics.RXErrors = iface.RXErrors
		if !iface.Up {
			addIssue(&snapshot, "interface_down", StatusCritical, "interface is administratively down")
		}
		if d.haveBaseline {
			elapsed := now.Sub(d.lastTime).Seconds()
			if elapsed > 0 {
				packets := counterDelta(iface.RXPackets, d.lastInterface.RXPackets)
				dropped := counterDelta(iface.RXDropped, d.lastInterface.RXDropped)
				snapshot.Metrics.RXPacketsDelta = packets
				snapshot.Metrics.RXDroppedDelta = dropped
				snapshot.Metrics.PPS = float64(packets) / elapsed
				total := packets + dropped
				if total > 0 {
					snapshot.Metrics.DropPct = float64(dropped) / float64(total) * 100
				}
			}
			if errors := counterDelta(iface.RXErrors, d.lastInterface.RXErrors); errors > 0 {
				addIssue(&snapshot, "rx_errors", StatusWarn, fmt.Sprintf("RX errors increased by %d", errors))
			}
		}
	}

	if d.cfg.ProcessName != "" || d.cfg.PIDFile != "" {
		process, err := d.probe.Process(d.cfg.PIDFile, d.cfg.ProcessName)
		snapshot.Process = process
		if err != nil {
			addIssue(&snapshot, "process_error", StatusCritical, "process probe failed: "+err.Error())
		} else if !process.Running {
			addIssue(&snapshot, "process_missing", StatusCritical, "ly_probe process is not running")
		}
	}

	softnetInfo, softnetErr := d.probe.Softnet()
	if softnetErr != nil {
		addIssue(&snapshot, "softnet_unavailable", StatusWarn, "softnet counters unavailable: "+softnetErr.Error())
	} else {
		snapshot.Metrics.SoftnetDropped = softnetInfo.Dropped
		if d.haveBaseline {
			delta := counterDelta(softnetInfo.Dropped, d.lastSoftnet.Dropped)
			snapshot.Metrics.SoftnetDelta = delta
			if delta > 0 {
				addIssue(&snapshot, "softnet_drops", StatusWarn, fmt.Sprintf("softnet dropped %d packets", delta))
			}
		}
	}

	ethtool, err := d.probe.Ethtool(d.cfg.Interface)
	if err != nil {
		addIssue(&snapshot, "ethtool_error", StatusWarn, "ethtool probe failed: "+err.Error())
	} else if !ethtool.Available {
		addIssue(&snapshot, "ethtool_unavailable", StatusWarn, "ethtool is not installed; ring/offload checks skipped")
	} else {
		snapshot.Metrics.EthtoolAvailable = true
		snapshot.Metrics.RingRX = ethtool.RingRX
		snapshot.Metrics.GRO = ethtool.GRO
		snapshot.Metrics.GSO = ethtool.GSO
		if ethtool.RingRX > 0 && ethtool.RingRX < d.cfg.RingMin {
			addIssue(&snapshot, "ring_small", StatusWarn, fmt.Sprintf("RX ring %d is below %d", ethtool.RingRX, d.cfg.RingMin))
		}
		if ethtool.GRO {
			addIssue(&snapshot, "gro_enabled", StatusWarn, "generic-receive-offload is enabled")
		}
		if ethtool.GSO {
			addIssue(&snapshot, "gso_enabled", StatusWarn, "generic-segmentation-offload is enabled")
		}
		if d.haveBaseline {
			snapshot.Metrics.RXMissedDelta = counterDelta(ethtool.RXMissed, d.lastEthtool.RXMissed)
			snapshot.Metrics.RXFIFODelta = counterDelta(ethtool.RXFIFO, d.lastEthtool.RXFIFO)
			snapshot.Metrics.RXOverDelta = counterDelta(ethtool.RXOver, d.lastEthtool.RXOver)
			snapshot.Metrics.NoBufferDelta = counterDelta(ethtool.NoBuffer, d.lastEthtool.NoBuffer)
			if snapshot.Metrics.RXMissedDelta > 0 {
				addIssue(&snapshot, "rx_missed", StatusWarn, fmt.Sprintf("RX missed errors increased by %d", snapshot.Metrics.RXMissedDelta))
			}
			if snapshot.Metrics.NoBufferDelta > 0 {
				addIssue(&snapshot, "rx_no_buffer", StatusWarn, fmt.Sprintf("RX no-buffer events increased by %d", snapshot.Metrics.NoBufferDelta))
			}
		}
	}
	snapshot.Metrics.PFRing = d.probe.PFRing()
	if !snapshot.Metrics.PFRing {
		addIssue(&snapshot, "pf_ring_unavailable", StatusWarn, "PF_RING is not loaded; using AF_PACKET fallback")
	}

	if snapshot.Metrics.DropPct >= d.cfg.DropCritPct {
		addIssue(&snapshot, "drop_critical", StatusCritical, fmt.Sprintf("drop rate %.2f%% >= %.2f%%", snapshot.Metrics.DropPct, d.cfg.DropCritPct))
	} else if snapshot.Metrics.DropPct >= d.cfg.DropWarnPct {
		addIssue(&snapshot, "drop_warning", StatusWarn, fmt.Sprintf("drop rate %.2f%% >= %.2f%%", snapshot.Metrics.DropPct, d.cfg.DropWarnPct))
	}

	snapshot.Status = worstStatus(snapshot.Issues)
	if snapshot.Status == StatusCritical {
		d.consecutiveCritical++
	} else {
		d.consecutiveCritical = 0
	}
	if snapshot.Status == StatusCritical &&
		d.consecutiveCritical >= d.cfg.RestartAfter &&
		now.Sub(d.lastRestart) >= d.cfg.RestartCooldown &&
		(d.cfg.RestartFunc != nil || len(d.cfg.RestartCommand) > 0) {
		addIssue(&snapshot, "restart", StatusCritical, fmt.Sprintf("executing configured restart after %d critical checks", d.consecutiveCritical))
		snapshot.Restarted = true
		d.cfg.Logger.Printf("capture doctor: CRITICAL: executing configured restart (consecutive=%d)", d.consecutiveCritical)
		if err := d.restart(ctx); err != nil {
			addIssue(&snapshot, "restart_failed", StatusCritical, "configured restart failed: "+err.Error())
		} else {
			d.lastRestart = now
			d.consecutiveCritical = 0
			d.cfg.Logger.Printf("capture doctor: restart command completed")
		}
	}

	if iface.Exists {
		d.lastInterface = iface
		d.lastEthtool = ethtool
		if softnetErr == nil {
			d.lastSoftnet = softnetInfo
		}
		d.lastTime = now
		d.haveBaseline = true
	}
	if len(snapshot.Issues) == 0 {
		d.cfg.Logger.Printf("capture doctor: status=ok")
	}
	return snapshot
}

func (d *Doctor) restart(ctx context.Context) error {
	if d.cfg.RestartFunc != nil {
		return d.cfg.RestartFunc(ctx)
	}
	command := exec.CommandContext(ctx, d.cfg.RestartCommand[0], d.cfg.RestartCommand[1:]...)
	output, err := command.CombinedOutput()
	if len(output) > 0 {
		d.cfg.Logger.Printf("capture doctor: restart output: %s", string(output))
	}
	return err
}

func addIssue(snapshot *Snapshot, code, severity, message string) {
	snapshot.Issues = append(snapshot.Issues, Issue{Code: code, Severity: severity, Message: message})
}

func worstStatus(issues []Issue) string {
	status := StatusOK
	for _, issue := range issues {
		if issue.Severity == StatusCritical {
			return StatusCritical
		}
		if issue.Severity == StatusWarn {
			status = StatusWarn
		}
	}
	return status
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

// WriteSnapshot atomically persists the latest status for the agent/UI.
func WriteSnapshot(path string, snapshot Snapshot) error {
	if path == "" {
		return nil
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

func ExitCode(status string) int {
	switch status {
	case StatusCritical:
		return 2
	case StatusWarn:
		return 1
	default:
		return 0
	}
}
