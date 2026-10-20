package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// eBPF process execution collector. It prefers a real sched_process_exec
// tracepoint via bpftrace and falls back to procfs/auditd when unavailable.
// The agent remains a static binary; bpftrace is an optional host capability.
type ebpfProcessCollector struct {
	agent  *Agent
	events chan ebpfProcessEvent
}

type ebpfProcessEvent struct {
	PID     int
	Command string
	Argv    string
}

func newEBPFProcessCollector(a *Agent) *ebpfProcessCollector {
	if a == nil || a.ctx == nil {
		return nil
	}
	path, err := exec.LookPath("bpftrace")
	if err != nil || strings.TrimSpace(path) == "" {
		return nil
	}
	collector := &ebpfProcessCollector{agent: a, events: make(chan ebpfProcessEvent, 512)}
	if !collector.start(path) {
		return nil
	}
	fmt.Printf("[hids] eBPF process collector active via %s\n", path)
	return collector
}

func (c *ebpfProcessCollector) start(bpftrace string) bool {
	script := `tracepoint:sched:sched_process_exec { printf("%d\t%s\t%s\n", pid, comm, str(args->filename)); }`
	cmd := exec.CommandContext(c.agent.ctx, bpftrace, "-q", "-e", script)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	go func() {
		_ = cmd.Wait()
	}()
	go func() {
		defer stdout.Close()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			fields := strings.SplitN(strings.TrimSpace(scanner.Text()), "\t", 3)
			if len(fields) < 2 {
				continue
			}
			pid, err := strconv.Atoi(fields[0])
			if err != nil || pid <= 0 {
				continue
			}
			event := ebpfProcessEvent{PID: pid, Command: strings.TrimSpace(fields[1])}
			if len(fields) > 2 {
				event.Argv = strings.TrimSpace(fields[2])
			}
			select {
			case c.events <- event:
				fmt.Printf("[hids] eBPF process exec: pid=%d comm=%s\n", event.PID, event.Command)
			default:
				// Keep the monitor non-blocking under a burst; procfs fallback
				// still observes the next snapshot.
			}
		}
	}()
	return true
}

func (c *ebpfProcessCollector) Collect(a *Agent, strategy string) []RuntimeEvent {
	if c == nil {
		return nil
	}
	events := make([]RuntimeEvent, 0, 8)
	for len(events) < 8 {
		select {
		case event := <-c.events:
			severity, signal := processSignal(processSnapshot{Name: event.Command, Cmdline: event.Argv})
			events = append(events, buildRuntimeMonitorEvent(
				a, "ebpf", "ebpf",
				"runtime.process.exec",
				severity,
				fmt.Sprintf("process exec observed: %s (pid=%d)", event.Command, event.PID),
				map[string]interface{}{
					"collector": "ebpf-sched-process-exec",
					"pid":       event.PID,
					"process":   event.Command,
					"cmdline":   event.Argv,
					"signal":    signal,
				},
			))
		default:
			return events
		}
	}
	return events
}

func selectRuntimeBackend(strategy string) string {
	if strategy != "ebpf" {
		return fallbackBackendLabel(strategy)
	}
	if _, err := exec.LookPath("bpftrace"); err == nil {
		return "ebpf"
	}
	return "procfs-fallback"
}
