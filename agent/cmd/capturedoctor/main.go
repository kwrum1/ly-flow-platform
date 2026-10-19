// Command capturedoctor monitors a ly_probe capture host and publishes a
// machine-readable health snapshot. Restart is opt-in and always reported.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ly-flow-platform/agent/capturedoctor"
)

func main() {
	iface := flag.String("interface", "", "capture interface")
	interval := flag.Duration("interval", 5*time.Second, "check interval")
	once := flag.Bool("once", false, "run one check and exit with 0/1/2")
	output := flag.String("output", "", "atomic JSON status file")
	pidFile := flag.String("pid-file", "", "optional ly_probe pid file")
	process := flag.String("process", "lyprobe", "process name to check; empty disables process check")
	dropWarn := flag.Float64("drop-warn", 1.0, "warning RX drop percentage")
	dropCrit := flag.Float64("drop-crit", 5.0, "critical RX drop percentage")
	ringMin := flag.Int("ring-min", 2048, "minimum RX ring entries")
	restartCommand := flag.String("restart-command", "", "opt-in command executed after repeated critical checks")
	restartAfter := flag.Int("restart-after", 3, "consecutive critical checks before restart")
	restartCooldown := flag.Duration("restart-cooldown", 5*time.Minute, "minimum time between restarts")
	alertCommand := flag.String("alert-command", "", "command invoked on status change/critical; JSON on stdin")
	jsonLog := flag.Bool("json", false, "print full JSON snapshots to stdout")
	flag.Parse()

	if strings.TrimSpace(*iface) == "" {
		log.Fatal("capturedoctor: -interface is required")
	}
	logger := log.New(os.Stderr, "capturedoctor: ", log.LstdFlags)
	config := capturedoctor.Config{
		Interface:       *iface,
		PIDFile:         *pidFile,
		ProcessName:     *process,
		DropWarnPct:     *dropWarn,
		DropCritPct:     *dropCrit,
		RingMin:         *ringMin,
		RestartAfter:    *restartAfter,
		RestartCooldown: *restartCooldown,
		Logger:          logger,
	}
	if command := strings.TrimSpace(*restartCommand); command != "" {
		config.RestartCommand = []string{"sh", "-c", command}
	}
	doctor := capturedoctor.New(config)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		snapshot := doctor.Check(ctx)
		emit(logger, snapshot, *output, *jsonLog)
		os.Exit(capturedoctor.ExitCode(snapshot.Status))
	}

	lastStatus := ""
	runCheck := func() {
		snapshot := doctor.Check(ctx)
		emit(logger, snapshot, *output, *jsonLog)
		shouldAlert := snapshot.Restarted || snapshot.Status != lastStatus
		lastStatus = snapshot.Status
		if shouldAlert && strings.TrimSpace(*alertCommand) != "" {
			if err := runAlert(ctx, *alertCommand, snapshot); err != nil {
				logger.Printf("alert command failed: %v", err)
			}
		}
	}
	runCheck()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return
			}
			logger.Printf("stopped: %v", ctx.Err())
			return
		case <-ticker.C:
			runCheck()
		}
	}
}

func emit(logger *log.Logger, snapshot capturedoctor.Snapshot, output string, jsonLog bool) {
	if err := capturedoctor.WriteSnapshot(output, snapshot); err != nil {
		logger.Printf("write status: %v", err)
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		logger.Printf("marshal snapshot: %v", err)
		return
	}
	if jsonLog {
		os.Stdout.Write(payload)
		os.Stdout.Write([]byte("\n"))
		return
	}
	logger.Printf("status=%s iface=%s pps=%.1f drop=%.2f%% issues=%d process=%v",
		snapshot.Status, snapshot.Interface, snapshot.Metrics.PPS, snapshot.Metrics.DropPct,
		len(snapshot.Issues), snapshot.Process.Running)
}

func runAlert(ctx context.Context, command string, snapshot capturedoctor.Snapshot) error {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdin = bytes.NewReader(payload)
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		log.Printf("alert output: %s", strings.TrimSpace(string(output)))
	}
	return err
}
