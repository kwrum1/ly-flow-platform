package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

const incidentProcessReadyPrefix = "INCIDENT_PROCESS_READY="

func TestIncidentLifecycle_real_process_checkpoint_postgres_restart_import_and_idempotent_rerun(t *testing.T) {
	// Given
	postgres := startIncidentLifecyclePostgres(t)
	binary := buildIncidentLifecycleServerBinary(t)
	oldServer := startIncidentLifecycleServerProcess(t, binary, "legacy", postgres.dsn)
	oldServer.putStatus(t, "inc-process-restart", "processing")

	// When
	oldServer.stop(t)
	postgres.restart(t)
	newServer := startIncidentLifecycleServerProcess(t, binary, "current", postgres.dsn)
	newServer.assertIncidentListContains(t, "inc-process-restart")
	newServer.assertIncidentStatus(t, "inc-process-restart", incidentlifecycle.StatusProcessing)
	newServer.stop(t)
	retriedServer := startIncidentLifecycleServerProcess(t, binary, "current", postgres.dsn)
	retriedServer.assertIncidentStatus(t, "inc-process-restart", incidentlifecycle.StatusProcessing)
	retriedServer.stop(t)

	// Then
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, postgres.dsn)
	if err != nil {
		t.Fatalf("connect restarted PostgreSQL: %v", err)
	}
	defer pool.Close()
	store := incidentlifecycle.NewPostgresStore(pool, time.Now)
	report, complete, err := store.LegacyCutover(ctx)
	if err != nil {
		t.Fatalf("read durable cutover: %v", err)
	}
	if !complete || report.Imported != 1 || report.AlreadyPersisted != 0 || report.Captured != 1 || report.Unrecoverable.TransitionHistory != 1 {
		t.Fatalf("durable original cutover report=%+v complete=%v", report, complete)
	}
	var audits, cutovers int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_audit WHERE action=$1`, incidentlifecycle.ActionSnapshot).Scan(&audits); err != nil {
		t.Fatalf("count process snapshot audits: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM incident_lifecycle_cutover_audit`).Scan(&cutovers); err != nil {
		t.Fatalf("count process cutovers: %v", err)
	}
	if audits != 1 || cutovers != 1 {
		t.Fatalf("process audit rows snapshot=%d cutover=%d", audits, cutovers)
	}
}

func TestIncidentLifecycle_real_main_binary_reports_checkpoint_failure_before_exit(t *testing.T) {
	// Given
	postgres := startIncidentLifecyclePostgres(t)
	binary := buildIncidentLifecycleServerBinary(t)
	process := startIncidentLifecycleServerProcess(t, binary, "failure", postgres.dsn)
	process.putStatus(t, "inc-process-failure", "processing")

	// When
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal failing server process: %v", err)
	}
	err := process.command.Wait()
	<-process.outputDone
	<-process.stderrDone

	// Then
	if err == nil {
		t.Fatal("checkpoint failure unexpectedly returned zero exit status")
	}
	output := process.output.String() + process.stderr.String()
	if !strings.Contains(output, "DEGRADED incident lifecycle shutdown checkpoint failed") || !strings.Contains(output, "checkpoint storage unavailable") {
		t.Fatalf("checkpoint degradation was not explicitly reported: %s", output)
	}
}

type incidentProcess struct {
	command    *exec.Cmd
	url        string
	output     *strings.Builder
	stderr     *bytes.Buffer
	outputDone <-chan struct{}
	stderrDone <-chan struct{}
}

func buildIncidentLifecycleServerBinary(t *testing.T) string {
	t.Helper()
	binary := t.TempDir() + "/ly-server-todo19"
	command := exec.Command("go", "build", "-o", binary, ".")
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build real server binary: %v: %s", err, output)
	}
	return binary
}

func startIncidentLifecycleServerProcess(t *testing.T, binary, mode, dsn string) *incidentProcess {
	t.Helper()
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "LYFLOW_INCIDENT_PROCESS_MODE="+mode, "LYFLOW_TEST_POSTGRES_DSN="+dsn)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatalf("open helper stderr: %v", err)
	}
	var output strings.Builder
	var stderrOutput bytes.Buffer
	outputDone := make(chan struct{})
	stderrDone := make(chan struct{})
	if err := command.Start(); err != nil {
		t.Fatalf("start %s server process: %v", mode, err)
	}
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			output.WriteString(scanner.Text())
			output.WriteByte('\n')
			if strings.HasPrefix(scanner.Text(), incidentProcessReadyPrefix) {
				select {
				case ready <- strings.TrimPrefix(scanner.Text(), incidentProcessReadyPrefix):
				default:
				}
			}
		}
		select {
		case ready <- "ERROR:" + output.String():
		default:
		}
		close(outputDone)
	}()
	go func() {
		_, _ = io.Copy(&stderrOutput, stderr)
		close(stderrDone)
	}()
	select {
	case url := <-ready:
		if strings.HasPrefix(url, "ERROR:") {
			t.Fatalf("%s server exited before readiness: %s", mode, strings.TrimPrefix(url, "ERROR:"))
		}
		return &incidentProcess{command: command, url: url, output: &output, stderr: &stderrOutput, outputDone: outputDone, stderrDone: stderrDone}
	case <-time.After(20 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("%s server readiness timed out", mode)
		return nil
	}
}

func (process *incidentProcess) stop(t *testing.T) {
	t.Helper()
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal server process: %v", err)
	}
	if err := process.command.Wait(); err != nil {
		t.Fatalf("wait server process: %v", err)
	}
	<-process.outputDone
	<-process.stderrDone
}
