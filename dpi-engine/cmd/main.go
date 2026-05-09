package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ly-flow-platform/dpi-engine/config"
	"ly-flow-platform/dpi-engine/core/domain"
	"ly-flow-platform/dpi-engine/core/engine"
	"ly-flow-platform/dpi-engine/core/output"
	"ly-flow-platform/dpi-engine/core/redis"
	"ly-flow-platform/dpi-engine/core/rules"
)

var (
	version = "v1.0.0"
	commit  = "dev"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("ly-dpi-engine %s (%s) starting...", version, commit)

	cfg := config.Load()

	// Initialize domain auditor
	auditor := domain.New()
	if err := auditor.LoadMiningList(cfg.Domain.MiningPath); err != nil {
		log.Printf("[config] Warning: failed to load mining list: %v", err)
	}
	if err := auditor.LoadFraudList(cfg.Domain.FraudPath); err != nil {
		log.Printf("[config] Warning: failed to load fraud list: %v", err)
	}
	if err := auditor.LoadCustomList(cfg.Domain.CustomPath); err != nil {
		log.Printf("[config] Warning: failed to load custom list: %v", err)
	}
	log.Printf("[domain] Auditor initialized")

	// Initialize rules engine
	ruleEngine := rules.New()
	if err := ruleEngine.LoadRulesFile(cfg.Rules.Path); err != nil {
		log.Printf("[config] Warning: failed to load rules: %v", err)
	}
	log.Printf("[rules] Loaded %d rules", ruleEngine.RuleCount())

	// Initialize Redis consumer
	consumer := redis.NewConsumer(
		cfg.Redis.Addr,
		cfg.Redis.Password,
		cfg.Redis.DB,
		cfg.Input.Stream,
		cfg.Output.Stream,
		cfg.Input.Group,
		cfg.Input.Consumer,
		cfg.Engine.Workers,
		cfg.Engine.BlockSeconds,
	)

	// Initialize output
	out := output.New(consumer.GetClient(), cfg.Output.Stream)

	// Initialize engine
	eng := engine.New(consumer, auditor, ruleEngine, out)

	// Start HTTP server for health and metrics
	mux := http.NewServeMux()
	setupRoutes(mux, eng)

	server := &http.Server{
		Addr:    cfg.HTTP.Addr,
		Handler: mux,
	}

	go func() {
		log.Printf("[http] Starting server on %s", cfg.HTTP.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[http] Server error: %v", err)
		}
	}()

	// Start engine
	if err := eng.Start(); err != nil {
		log.Fatalf("[engine] Failed to start: %v", err)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[main] Shutdown signal received")

	// Graceful shutdown
	eng.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[http] Shutdown error: %v", err)
	}

	flows, alerts, matched := eng.Stats()
	log.Printf("[main] Shutdown complete (flows: %d, alerts: %d, matched: %d)",
		flows, alerts, matched)
}

func setupRoutes(mux *http.ServeMux, eng *engine.Engine) {
	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"ly-dpi-engine"}`))
	})

	// Stats endpoint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		flows, alerts, matched := eng.Stats()
		fmt.Fprintf(w, `{"flows":%d,"alerts":%d,"matched":%d,"version":"%s"}`,
			flows, alerts, matched, version)
	})

	// Prometheus metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		flows, alerts, matched := eng.Stats()
		proc, alrt, err := eng.ConsumerStats()
		sent, outErr := eng.OutputStats()

		fmt.Fprintf(w, "# HELP dpi_engine_flows_total Total flows processed\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_flows_total counter\n")
		fmt.Fprintf(w, "dpi_engine_flows_total %d\n", flows)
		fmt.Fprintf(w, "# HELP dpi_engine_alerts_total Total alerts generated\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_alerts_total counter\n")
		fmt.Fprintf(w, "dpi_engine_alerts_total %d\n", alerts)
		fmt.Fprintf(w, "# HELP dpi_engine_matched_total Total rules matched\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_matched_total counter\n")
		fmt.Fprintf(w, "dpi_engine_matched_total %d\n", matched)
		fmt.Fprintf(w, "# HELP dpi_engine_processed_total Total messages processed\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_processed_total counter\n")
		fmt.Fprintf(w, "dpi_engine_processed_total %d\n", proc)
		fmt.Fprintf(w, "# HELP dpi_engine_errors_total Total errors\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_errors_total counter\n")
		fmt.Fprintf(w, "dpi_engine_redis_errors_total %d\n", err)
		fmt.Fprintf(w, "# HELP dpi_engine_sent_total Total alerts sent\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_sent_total counter\n")
		fmt.Fprintf(w, "dpi_engine_sent_total %d\n", sent)
		fmt.Fprintf(w, "# HELP dpi_engine_output_errors_total Total output errors\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_output_errors_total counter\n")
		fmt.Fprintf(w, "dpi_engine_output_errors_total %d\n", outErr)
		_ = alrt
	})

	// Version endpoint
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"%s","commit":"%s"}`, version, commit)
	})
}