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

	"ly-flow-platform/probe/config"
	"ly-flow-platform/probe/core/capture"
	"ly-flow-platform/probe/core/processor"
	"ly-flow-platform/probe/core/redis"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("ly-probe v%s (build: %s)", Version, BuildTime)

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set sensor ID from hostname if not configured
	if cfg.SensorID == "" {
		hostname, _ := os.Hostname()
		cfg.SensorID = hostname
	}

	log.Printf("Configuration loaded:")
	log.Printf("  Redis: %s/%s", cfg.RedisAddr, cfg.RedisStream)
	log.Printf("  Capture Interface: %s", cfg.CaptureInterface)
	log.Printf("  Sensor ID: %s", cfg.SensorID)

	// Initialize Redis producer
	producer, err := redis.NewProducer(
		cfg.RedisAddr,
		cfg.RedisPassword,
		cfg.RedisDB,
		cfg.RedisStream,
		cfg.BatchSize,
		time.Duration(cfg.FlushInterval)*time.Second,
	)
	if err != nil {
		log.Fatalf("Failed to create Redis producer: %v", err)
	}
	defer producer.Stop()
	producer.Start()

	// Initialize packet processor
	proc := processor.NewProcessor(cfg.SensorID)

	// Initialize packet capture
	captureInst, err := capture.NewCapture(
		cfg.CaptureInterface,
		cfg.CaptureBPFFilter,
		cfg.CaptureSnapLen,
		cfg.CapturePromisc,
	)
	if err != nil {
		log.Fatalf("Failed to create capture: %v", err)
	}

	// Set packet handler
	var processedCount int64
	var flowCount int64
	captureInst.OnPacket(func(data []byte) {
		flow := proc.ProcessPacket(data)
		if flow != nil {
			if err := producer.Send(flow); err != nil {
				log.Printf("Error sending flow: %v", err)
			} else {
				processedCount++
				if processedCount%100 == 0 {
					log.Printf("Processed %d packets, %d flows", processedCount, flowCount)
				}
			}
			flowCount++
		}
	})

	// Start capture
	if err := captureInst.Start(); err != nil {
		log.Fatalf("Failed to start capture: %v", err)
	}
	log.Printf("Packet capture started on %s", cfg.CaptureInterface)

	// Start periodic flow cleanup
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				removed := proc.Cleanup(5 * time.Minute)
				if removed > 0 {
					log.Printf("Cleaned up %d stale flows", removed)
				}
			}
		}
	}()

	// Start health check server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"%s","processed":%d,"flows":%d}`,
			Version, processedCount, flowCount)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "# HELP ly_probe_packets_total Total packets processed\n")
		fmt.Fprintf(w, "# TYPE ly_probe_packets_total counter\n")
		fmt.Fprintf(w, "ly_probe_packets_total %d\n", processedCount)
		fmt.Fprintf(w, "# HELP ly_probe_flows_total Total flows detected\n")
		fmt.Fprintf(w, "TYPE ly_probe_flows_total counter\n")
		fmt.Fprintf(w, "ly_probe_flows_total %d\n", flowCount)
	})

	healthServer := &http.Server{
		Addr:    cfg.HealthCheckAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("Health check server listening on %s", cfg.HealthCheckAddr)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop capture first
	if err := captureInst.Stop(); err != nil {
		log.Printf("Error stopping capture: %v", err)
	}

	// Shutdown health server
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Error shutting down health server: %v", err)
	}

	log.Printf("Shutdown complete. Processed %d packets, %d flows", processedCount, flowCount)
}
