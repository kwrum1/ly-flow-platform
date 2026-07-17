package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"ly-flow-platform/security-engine/config"
	"ly-flow-platform/security-engine/engine"
)

func main() {
	if err := config.ValidateLegacyRASPEnvironment(); err != nil {
		log.Fatalf("[security-engine] RASP policy configuration rejected: %v", err)
	}
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("[security-engine] stopped: %v", err)
	}
}

func run(ctx context.Context, cfg config.Config) error {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	control, err := newReloadControl(cfg.ControlToken, cfg.ReloadAuditPath)
	if err != nil {
		return err
	}
	username, password := cfg.RedisUsername, cfg.RedisPassword
	if username == "" || password == "" {
		username, password = "", cfg.RedisLegacyPassword
	}
	client := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Username: username, Password: password})
	defer client.Close()

	if err := client.Ping(runCtx).Err(); err != nil {
		return fmt.Errorf("redis unavailable: %w", err)
	}
	eng := engine.New(cfg, client)
	bundle, manifest, err := engine.LoadLifecycleBundle(cfg.LifecycleManifest, cfg.RuleTrustRoot, cfg.BundleRoot)
	if err != nil {
		return fmt.Errorf("load verified active lifecycle: %w", err)
	}
	eng.Activate(bundle, manifest)
	log.Printf("[security-engine] loaded verified lifecycle bundle %s", bundle.Version)
	engineDone := make(chan error, 1)
	go func() {
		engineDone <- eng.Supervise(runCtx)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snapshot, snapshotErr := eng.SnapshotContext(r.Context())
		if snapshotErr != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			log.Printf("[security-engine] encode health response failed: %v", err)
		}
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"service": "ly-security-engine", "ready": true})
	})

	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		principal, role, authorizationStatus := control.authorize(r)
		if authorizationStatus != http.StatusOK {
			if err := control.record(principal, role, "denied", "authorization", "", ""); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "reload_audit_unavailable"})
				return
			}
			w.WriteHeader(authorizationStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": http.StatusText(authorizationStatus)})
			return
		}
		if r.Method != http.MethodPost {
			if !recordReloadFailure(w, control, principal, role, "method", "") {
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "method_not_allowed"})
			return
		}
		var req struct {
			ManifestPath string `json:"manifest_path"`
			SHA256       string `json:"sha256"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil || strings.TrimSpace(req.ManifestPath) == "" || strings.TrimSpace(req.SHA256) == "" {
			if !recordReloadFailure(w, control, principal, role, "request", "") {
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_lifecycle_manifest"})
			return
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			if !recordReloadFailure(w, control, principal, role, "request", "") {
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_lifecycle_manifest"})
			return
		}
		if filepath.Clean(req.ManifestPath) != filepath.Clean(cfg.LifecycleManifest) {
			if !recordReloadFailure(w, control, principal, role, "manifest_path", "") {
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "inactive_lifecycle_manifest"})
			return
		}
		bundle, verified, err := engine.LoadLifecycleBundle(req.ManifestPath, cfg.RuleTrustRoot, cfg.BundleRoot)
		if err != nil {
			if !recordReloadFailure(w, control, principal, role, "verification", "") {
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "lifecycle_verification_failed", "message": err.Error()})
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(req.SHA256)), []byte(verified.Digest)) != 1 {
			if !recordReloadFailure(w, control, principal, role, "digest", verified.Revision) {
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "lifecycle_digest_mismatch"})
			return
		}
		if err := control.record(principal, role, "succeeded", "activation", verified.Revision, verified.Digest); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "reload_audit_unavailable"})
			return
		}
		eng.Activate(bundle, verified)
		log.Printf("[security-engine] reloaded verified lifecycle bundle %s", bundle.Version)
		snapshot, snapshotErr := eng.SnapshotContext(r.Context())
		if snapshotErr != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if err := json.NewEncoder(w).Encode(snapshot); err != nil {
			log.Printf("[security-engine] encode reload response failed: %v", err)
		}
	})

	server := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ListenAndServe()
	}()
	log.Printf("[security-engine] listening on %s", cfg.HTTPAddr)
	select {
	case err := <-engineDone:
		cancelRun()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		serverErr := <-serverDone
		if errors.Is(serverErr, http.ErrServerClosed) {
			serverErr = nil
		}
		if err != nil {
			return errors.Join(fmt.Errorf("engine supervision: %w", err), shutdownErr, serverErr)
		}
		return errors.Join(shutdownErr, serverErr)
	case err := <-serverDone:
		cancelRun()
		engineErr := <-engineDone
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.Join(fmt.Errorf("http server: %w", err), engineErr)
		}
		return engineErr
	case <-ctx.Done():
		cancelRun()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		if err := <-serverDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server shutdown: %w", err)
		}
		if err := <-engineDone; err != nil {
			return fmt.Errorf("engine shutdown: %w", err)
		}
		return nil
	}
}
