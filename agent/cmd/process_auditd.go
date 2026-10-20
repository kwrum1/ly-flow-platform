package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// auditdProcessCollector is the second-choice process source. It tails the
// kernel audit log and turns EXECVE/SYSCALL records into the same runtime
// process events as the eBPF collector. It is used only when bpftrace/BPF is
// unavailable; procfs snapshots remain the final fallback.
type auditdProcessCollector struct {
	agent  *Agent
	events chan auditdProcessEvent
}

type auditdProcessEvent struct {
	PID     int
	Command string
	Exe     string
}

var auditdCommPattern = regexp.MustCompile(`\bcomm="([^"]+)"`)
var auditdExePattern = regexp.MustCompile(`\bexe="([^"]+)"`)
var auditdPIDPattern = regexp.MustCompile(`\bpid=(\d+)`)

func newAuditdProcessCollector(a *Agent) *auditdProcessCollector {
	if a == nil || a.ctx == nil {
		return nil
	}
	paths := []string{"/var/log/audit/audit.log", "/var/log/audit/audit.log.1"}
	var file *os.File
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			handle, err := os.Open(path)
			if err == nil {
				file = handle
				break
			}
		}
	}
	if file == nil {
		return nil
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil
	}
	collector := &auditdProcessCollector{agent: a, events: make(chan auditdProcessEvent, 512)}
	go collector.tail(file)
	return collector
}

func (c *auditdProcessCollector) tail(file *os.File) {
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		select {
		case <-c.agent.ctx.Done():
			return
		default:
		}
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			if event, ok := parseAuditdExec(line); ok {
				select {
				case c.events <- event:
				default:
				}
			}
		}
		if err != nil {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func parseAuditdExec(line string) (auditdProcessEvent, bool) {
	if !strings.Contains(line, "type=EXECVE") && !strings.Contains(line, "type=SYSCALL") {
		return auditdProcessEvent{}, false
	}
	commMatch := auditdCommPattern.FindStringSubmatch(line)
	exeMatch := auditdExePattern.FindStringSubmatch(line)
	pidMatch := auditdPIDPattern.FindStringSubmatch(line)
	if len(commMatch) < 2 && len(exeMatch) < 2 {
		return auditdProcessEvent{}, false
	}
	command := "unknown"
	if len(commMatch) > 1 {
		command = commMatch[1]
	} else if len(exeMatch) > 1 {
		command = filepathBase(exeMatch[1])
	}
	event := auditdProcessEvent{Command: command}
	if len(exeMatch) > 1 {
		event.Exe = exeMatch[1]
	}
	if len(pidMatch) > 1 {
		fmt.Sscanf(pidMatch[1], "%d", &event.PID)
	}
	return event, true
}

func filepathBase(path string) string {
	path = strings.TrimRight(path, "/")
	if index := strings.LastIndex(path, "/"); index >= 0 {
		return path[index+1:]
	}
	return path
}

func (c *auditdProcessCollector) Collect(a *Agent, strategy string) []RuntimeEvent {
	if c == nil {
		return nil
	}
	events := make([]RuntimeEvent, 0, 8)
	for len(events) < 8 {
		select {
		case event := <-c.events:
			severity, signal := processSignal(processSnapshot{Name: event.Command, Cmdline: event.Exe})
			events = append(events, buildRuntimeMonitorEvent(
				a, "auditd", "auditd",
				"runtime.process.exec",
				severity,
				fmt.Sprintf("process exec observed: %s (pid=%d)", event.Command, event.PID),
				map[string]interface{}{
					"collector": "auditd-execve",
					"pid":       event.PID,
					"process":   event.Command,
					"cmdline":   event.Exe,
					"signal":    signal,
				},
			))
		default:
			return events
		}
	}
	return events
}
