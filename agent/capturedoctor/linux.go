//go:build linux

package capturedoctor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type LinuxProbe struct{}

func (LinuxProbe) Now() time.Time { return time.Now() }

func (LinuxProbe) Interface(name string) (InterfaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceInfo{Exists: false}, nil
	}
	info := InterfaceInfo{
		Exists: true,
		Up:     iface.Flags&net.FlagUp != 0,
		MTU:    iface.MTU,
	}
	payload, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return info, err
	}
	parsed, ok := parseNetDev(string(payload), name)
	if !ok {
		return info, fmt.Errorf("interface %s not present in /proc/net/dev", name)
	}
	parsed.Exists = true
	parsed.Up = info.Up
	parsed.MTU = info.MTU
	return parsed, nil
}

func (LinuxProbe) Softnet() (SoftnetInfo, error) {
	payload, err := os.ReadFile("/proc/net/softnet_stat")
	if err != nil {
		return SoftnetInfo{}, err
	}
	return parseSoftnet(string(payload))
}

func (LinuxProbe) Ethtool(name string) (EthtoolInfo, error) {
	if _, err := exec.LookPath("ethtool"); err != nil {
		return EthtoolInfo{Available: false}, nil
	}
	info := EthtoolInfo{Available: true}
	var lastErr error
	if output, err := runEthtool("-g", name); err != nil {
		lastErr = err
	} else {
		info.RingRX = parseRingRX(output)
	}
	if output, err := runEthtool("-k", name); err != nil {
		lastErr = err
	} else {
		info.GRO = featureOn(output, "generic-receive-offload")
		info.GSO = featureOn(output, "tx-generic-segmentation") || featureOn(output, "tx-gso")
	}
	if output, err := runEthtool("-S", name); err != nil {
		lastErr = err
	} else {
		stats := parseEthtoolStats(output)
		info.RXMissed = stats["rx_missed_errors"]
		info.RXFIFO = stats["rx_fifo_errors"]
		info.RXOver = stats["rx_over_errors"]
		info.NoBuffer = stats["rx_no_buffer_count"]
	}
	if info.RingRX == 0 && info.RXMissed == 0 && !info.GRO && !info.GSO && lastErr != nil {
		return info, lastErr
	}
	return info, nil
}

func (LinuxProbe) Process(pidFile, name string) (ProcessInfo, error) {
	if pidFile != "" {
		payload, err := os.ReadFile(pidFile)
		if err != nil {
			return ProcessInfo{Name: name}, nil
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(payload)))
		if err != nil {
			return ProcessInfo{Name: name}, fmt.Errorf("invalid pid file: %w", err)
		}
		return processInfo(pid, name)
	}
	if name == "" {
		return ProcessInfo{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "pgrep", "-x", name).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return ProcessInfo{Name: name, Running: false}, nil
		}
		return ProcessInfo{Name: name}, err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return ProcessInfo{Name: name, Running: false}, nil
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return ProcessInfo{Name: name}, err
	}
	return processInfo(pid, name)
}

func (LinuxProbe) PFRing() bool {
	_, err := os.Stat("/proc/net/pf_ring")
	return err == nil
}

func processInfo(pid int, name string) (ProcessInfo, error) {
	process, err := os.FindProcess(pid)
	if err != nil {
		return ProcessInfo{Name: name, PID: pid}, err
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		if err == os.ErrProcessDone || err == syscall.ESRCH {
			return ProcessInfo{Name: name, PID: pid, Running: false}, nil
		}
		return ProcessInfo{Name: name, PID: pid}, err
	}
	info := ProcessInfo{Name: name, PID: pid, Running: true}
	if payload, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(payload)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.RSSKB, _ = strconv.Atoi(fields[1])
				}
				break
			}
		}
	}
	return info, nil
}

func runEthtool(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ethtool", args...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("ethtool %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func parseNetDev(payload, name string) (InterfaceInfo, bool) {
	scanner := bufio.NewScanner(strings.NewReader(payload))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		if strings.TrimSpace(line[:idx]) != name {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 4 {
			return InterfaceInfo{Exists: true}, false
		}
		info := InterfaceInfo{Exists: true}
		info.RXPackets = parseUint(fields[1])
		info.RXErrors = parseUint(fields[2])
		info.RXDropped = parseUint(fields[3])
		if len(fields) > 4 {
			info.RXFIFO = parseUint(fields[4])
		}
		return info, true
	}
	return InterfaceInfo{Exists: false}, false
}

func parseSoftnet(payload string) (SoftnetInfo, error) {
	var result SoftnetInfo
	scanner := bufio.NewScanner(strings.NewReader(payload))
	lines := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		lines++
		if dropped, err := strconv.ParseUint(fields[1], 16, 64); err == nil {
			result.Dropped += dropped
		}
		if len(fields) > 2 {
			if squeezed, err := strconv.ParseUint(fields[2], 16, 64); err == nil {
				result.Squeezed += squeezed
			}
		}
	}
	if lines == 0 {
		return result, fmt.Errorf("empty softnet statistics")
	}
	return result, nil
}

func parseRingRX(output string) int {
	current := false
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Current hardware settings") {
			current = true
			continue
		}
		if current && strings.HasPrefix(line, "RX:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.Atoi(fields[1])
				return value
			}
		}
	}
	return 0
}

func featureOn(output, name string) bool {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, name+":") {
			continue
		}
		return strings.HasSuffix(line, ": on")
	}
	return false
}

func parseEthtoolStats(output string) map[string]uint64 {
	stats := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value, err := strconv.ParseUint(strings.TrimSpace(line[idx+1:]), 10, 64)
		if err == nil {
			stats[key] = value
		}
	}
	return stats
}

func parseUint(value string) uint64 {
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed
}
