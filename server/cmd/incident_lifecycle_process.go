package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

type unavailableIncidentCheckpointer struct{}

func (unavailableIncidentCheckpointer) CheckpointLegacySnapshot(context.Context, []incidentlifecycle.LegacyStatus, string) (incidentlifecycle.SnapshotReport, error) {
	return incidentlifecycle.SnapshotReport{}, errors.New("checkpoint storage unavailable")
}

func runIncidentLifecycleProcess() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("LYFLOW_TEST_POSTGRES_DSN"))
	if err != nil {
		return fmt.Errorf("connect PostgreSQL: %w", err)
	}
	defer pool.Close()
	store := incidentlifecycle.NewPostgresStore(pool, time.Now)
	if err := store.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("ensure incident lifecycle schema: %w", err)
	}
	mode := os.Getenv("LYFLOW_INCIDENT_PROCESS_MODE")
	config := &Config{DBPool: pool, IncidentCheckpoint: store, IncidentSnapshot: &incidentSnapshotState{}, IncidentLegacyMode: mode != "current"}
	if mode == "current" {
		now := time.Now().UTC()
		snapshot, err := incidentlifecycle.NewActiveSnapshot(incidentlifecycle.ActiveAlgorithm, []incidentlifecycle.Candidate{{IncidentID: "inc-process-restart", SourceChainID: "chain-process-restart", Severity: "high", FirstSeen: now.Add(-time.Minute), LastSeen: now}})
		if err != nil {
			return fmt.Errorf("create active incident snapshot: %w", err)
		}
		if _, err := store.SyncActive(ctx, snapshot); err != nil {
			return fmt.Errorf("sync active incident snapshot: %w", err)
		}
		if err := initializeIncidentLifecycleRuntime(ctx, config); err != nil {
			return fmt.Errorf("initialize incident lifecycle runtime: %w", err)
		}
	}
	if mode == "failure" {
		config.IncidentCheckpoint = unavailableIncidentCheckpointer{}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/incidents", incidentsHandler(config))
	mux.HandleFunc("/api/v1/incidents/", incidentDetailHandler(config))
	mux.HandleFunc("/api/v1/admin/incident-lifecycle/checkpoint", incidentLifecycleCheckpointHandler(config))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	fmt.Printf("INCIDENT_PROCESS_READY=http://%s\n", listener.Addr())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	select {
	case <-signals:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		shutdownErr := server.Shutdown(shutdownCtx)
		shutdownCancel()
		if shutdownErr != nil {
			return fmt.Errorf("shutdown server: %w", shutdownErr)
		}
		if config.IncidentLegacyMode {
			checkpointCtx, checkpointCancel := context.WithTimeout(context.Background(), 10*time.Second)
			report, checkpointErr := checkpointIncidentLifecycleOnShutdown(checkpointCtx, config)
			checkpointCancel()
			if checkpointErr != nil {
				log.Printf("DEGRADED incident lifecycle shutdown checkpoint failed: captured=%d unrecoverable=%d cutover_marked=%v error=%v", report.Captured, report.Unrecoverable.Total(), report.CutoverMarked, checkpointErr)
				return fmt.Errorf("incident lifecycle shutdown checkpoint: %w", checkpointErr)
			}
			log.Printf("incident lifecycle shutdown checkpoint completed: captured=%d checksum=%s cutover_marked=%v", report.Captured, report.SnapshotChecksum, report.CutoverMarked)
		}
		return nil
	case err := <-serveDone:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
}
