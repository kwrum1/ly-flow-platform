package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

type incidentPostgresProcess struct {
	name   string
	volume string
	dsn    string
}

func startIncidentLifecyclePostgres(t *testing.T) *incidentPostgresProcess {
	t.Helper()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	postgres := &incidentPostgresProcess{name: "lyflow-todo19-pg-" + suffix, volume: "lyflow-todo19-data-" + suffix}
	runDocker(t, "volume", "create", postgres.volume)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", postgres.name).Run()
		_ = exec.Command("docker", "volume", "rm", "-f", postgres.volume).Run()
	})
	runDocker(t, "run", "-d", "--pull=never", "--name", postgres.name,
		"-e", "POSTGRES_DB=todo19", "-e", "POSTGRES_USER=todo19", "-e", "POSTGRES_PASSWORD=todo19-password",
		"-p", "127.0.0.1::5432", "-v", postgres.volume+":/var/lib/postgresql/data", "postgres:16-alpine")
	postgres.refreshDSN(t)
	postgres.waitReady(t)
	return postgres
}

func (postgres *incidentPostgresProcess) restart(t *testing.T) {
	t.Helper()
	runDocker(t, "stop", "--time", "10", postgres.name)
	runDocker(t, "start", postgres.name)
	postgres.refreshDSN(t)
	postgres.waitReady(t)
}

func (postgres *incidentPostgresProcess) refreshDSN(t *testing.T) {
	t.Helper()
	portOutput := runDocker(t, "port", postgres.name, "5432/tcp")
	_, port, found := strings.Cut(strings.TrimSpace(portOutput), ":")
	if !found {
		t.Fatalf("parse PostgreSQL port output %q", portOutput)
	}
	postgres.dsn = "postgres://todo19:todo19-password@127.0.0.1:" + port + "/todo19?sslmode=disable"
}

func (postgres *incidentPostgresProcess) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			pool, err := pgxpool.New(ctx, postgres.dsn)
			if err == nil {
				err = pool.Ping(ctx)
				pool.Close()
			}
			cancel()
			if err == nil {
				return
			}
		case <-deadline.C:
			logs, _ := exec.Command("docker", "logs", postgres.name).CombinedOutput()
			state, _ := exec.Command("docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}} {{.NetworkSettings.Ports}}", postgres.name).CombinedOutput()
			t.Fatalf("disposable PostgreSQL readiness timed out: state=%s logs=%s", state, logs)
		}
	}
}

func runDocker(t *testing.T, args ...string) string {
	t.Helper()
	output, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func (process *incidentProcess) putStatus(t *testing.T, incidentID, status string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPut, process.url+"/api/v1/incidents/"+incidentID+"/status", strings.NewReader(`{"status":"`+status+`"}`))
	if err != nil {
		t.Fatalf("create legacy status request: %v", err)
	}
	response, err := incidentProcessHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("write legacy incident status: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("legacy status response=%d body=%s", response.StatusCode, body)
	}
}

func checkpointLegacyServer(t *testing.T, baseURL string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/incident-lifecycle/checkpoint", nil)
	if err != nil {
		t.Fatalf("create checkpoint request: %v", err)
	}
	response, err := incidentProcessHTTPClient().Do(request)
	if err != nil {
		t.Fatalf("invoke legacy checkpoint: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("checkpoint response=%d body=%s", response.StatusCode, body)
	}
}

func (process *incidentProcess) assertIncidentStatus(t *testing.T, incidentID string, expected incidentlifecycle.Status) {
	t.Helper()
	response, err := incidentProcessHTTPClient().Get(process.url + "/api/v1/incidents/" + incidentID)
	if err != nil {
		t.Fatalf("read imported incident: %v", err)
	}
	defer response.Body.Close()
	var envelope struct {
		Data struct {
			Status incidentlifecycle.Status `json:"status"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode imported incident: %v", err)
	}
	if response.StatusCode != http.StatusOK || envelope.Data.Status != expected {
		t.Fatalf("imported incident response=%d status=%s", response.StatusCode, envelope.Data.Status)
	}
}

func incidentProcessHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
