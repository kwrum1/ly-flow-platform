package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
	"ly-flow-platform/security-engine/engine"
)

func main() {
	cfg := config.Load()
	client := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("[security-engine] redis unavailable: %v", err)
	}
	eng := engine.New(cfg, client)
	if bundle, err := engine.LoadBundleFile(cfg.BundlePath); err == nil {
		eng.Reload(bundle)
		log.Printf("[security-engine] loaded bundle %s", bundle.Version)
	} else {
		log.Printf("[security-engine] bundle not loaded (%s): %v", cfg.BundlePath, err)
	}
	go eng.Run(ctx)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(eng.Snapshot())
	})
	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"service": "ly-security-engine", "ready": true})
	})

	http.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "method_not_allowed"})
			return
		}
		var req struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_path"})
			return
		}
		bundle, err := engine.LoadBundleFile(req.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "bundle_load_failed", "message": err.Error()})
			return
		}
		eng.Reload(bundle)
		log.Printf("[security-engine] reloaded bundle %s from %s", bundle.Version, req.Path)
		_ = json.NewEncoder(w).Encode(eng.Snapshot())
	})

	server := &http.Server{Addr: cfg.HTTPAddr}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	log.Printf("[security-engine] listening on %s", cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("[security-engine] http failed: %v", err)
	}
}
