package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type reloadAuditRecorder struct{}

func (reloadAuditRecorder) Record(context.Context, rulelifecycle.AuditEvent) error { return nil }

func TestCompileDefaultSecurityBundleRestoresStateWhenReloadEventCommitFails(t *testing.T) {
	// Given
	postgres := startIncidentLifecyclePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	ctx = context.WithValue(ctx, auth.UserContextKey, int64(1))
	ctx = context.WithValue(ctx, auth.RoleContextKey, auth.RoleAdmin)
	pool, err := pgxpool.New(ctx, postgres.dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := ensureRuntimeSchema(ctx, pool); err != nil {
		t.Fatalf("apply runtime schema: %v", err)
	}
	packageDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	repositoryRoot := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	t.Chdir(repositoryRoot)
	root := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(root, "trust"), KeyDir: filepath.Join(root, "keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		t.Fatalf("ensure trust roots: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.RuleSigner)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	runtime := &ruleSyncRuntime{state: rulelifecycle.RuntimeState{ManifestPath: "/runtime/bootstrap.json", Revision: "bootstrap", Digest: "bootstrap-digest"}}
	manager, err := rulelifecycle.NewManager(rulelifecycle.ManagerConfig{
		RootDir: filepath.Join(root, "lifecycle"), Signer: signer, Verifier: layout,
		Audit: reloadAuditRecorder{}, Runtime: runtime, Now: time.Now,
	})
	if err != nil {
		t.Fatalf("create lifecycle manager: %v", err)
	}
	baselinePath := os.Getenv("LYFLOW_RELOAD_BASELINE_BUNDLE")
	baselineVersion := os.Getenv("LYFLOW_RELOAD_BASELINE_VERSION")
	var baselineBytes []byte
	if baselinePath == "" && baselineVersion == "" {
		baselinePath = "rules/security-engine/default-bundle.json"
		baselineVersion = "t08-baseline"
		baselineBytes, err = os.ReadFile(baselinePath)
		if err != nil {
			t.Fatalf("read baseline bundle: %v", err)
		}
		var baseline compiledBundleFile
		if err := json.Unmarshal(baselineBytes, &baseline); err != nil {
			t.Fatalf("decode baseline bundle: %v", err)
		}
		baseline.Version = baselineVersion
		baselineBytes, err = json.Marshal(baseline)
		if err != nil {
			t.Fatalf("encode baseline bundle: %v", err)
		}
	} else {
		if baselinePath == "" || baselineVersion == "" {
			t.Fatal("LYFLOW_RELOAD_BASELINE_BUNDLE and LYFLOW_RELOAD_BASELINE_VERSION must be set together")
		}
		baselineBytes, err = os.ReadFile(baselinePath)
		if err != nil {
			t.Fatalf("read configured baseline bundle: %v", err)
		}
	}
	baselineDigest := sha256.Sum256(baselineBytes)
	actor := rulelifecycle.Actor{ID: "user:1", Role: rulelifecycle.RoleAdmin}
	if _, err := manager.StageLocal(ctx, actor, rulelifecycle.LocalSource{
		SourceID: baselineVersion, Revision: baselineVersion,
		SHA256: hex.EncodeToString(baselineDigest[:]), Content: baselineBytes,
	}); err != nil {
		t.Fatalf("stage baseline: %v", err)
	}
	baselineManifest, err := manager.Activate(ctx, actor, baselineVersion)
	if err != nil {
		t.Fatalf("activate baseline: %v", err)
	}
	beforeRuntime := runtime.state
	if _, err := pool.Exec(ctx, `INSERT INTO rule_bundles (version,status,bundle_hash,bundle_path,activated_at) VALUES ($1,'active',$2,$3,NOW())`, baselineVersion, baselineManifest.Digest, baselineManifest.BundlePath); err != nil {
		t.Fatalf("record baseline bundle: %v", err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE rule_hot_reload_events`); err != nil {
		t.Fatalf("inject event persistence failure: %v", err)
	}
	cfg := &Config{DBPool: pool, RuleLifecycle: manager}

	// When
	_, compileErr := compileDefaultSecurityBundle(ctx, cfg)
	active, activeErr := manager.Active(ctx)

	// Then
	if compileErr == nil || activeErr != nil {
		t.Fatalf("compile error=%v active error=%v", compileErr, activeErr)
	}
	if active.Revision != baselineVersion || runtime.state != beforeRuntime {
		t.Fatalf("failed commit changed state: active=%s runtime=%#v want=%s/%#v", active.Revision, runtime.state, baselineVersion, beforeRuntime)
	}
	var activeRows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_bundles WHERE status='active'`).Scan(&activeRows); err != nil {
		t.Fatalf("count active bundles: %v", err)
	}
	if activeRows != 1 {
		t.Fatalf("failed commit left %d active database bundle rows, want baseline only", activeRows)
	}
	if err := ensureRuntimeSchema(ctx, pool); err != nil {
		t.Fatalf("restore reload event schema: %v", err)
	}
	runtime.mu.Lock()
	runtime.failHealth = true
	runtime.mu.Unlock()
	_, healthErr := compileDefaultSecurityBundle(ctx, cfg)
	activeAfterHealth, activeAfterHealthErr := manager.Active(ctx)
	if healthErr == nil || activeAfterHealthErr != nil {
		t.Fatalf("health failure=%v active error=%v", healthErr, activeAfterHealthErr)
	}
	if activeAfterHealth.Revision != baselineVersion || runtime.state != beforeRuntime {
		t.Fatalf("health failure changed state: active=%s runtime=%#v", activeAfterHealth.Revision, runtime.state)
	}
	var failedEvents int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_hot_reload_events WHERE status='failed'`).Scan(&failedEvents); err != nil {
		t.Fatalf("count failed reload events: %v", err)
	}
	if failedEvents != 1 {
		t.Fatalf("failed reload event rows=%d, want 1", failedEvents)
	}
	runtime.mu.Lock()
	runtime.failHealth = false
	runtime.mu.Unlock()
	success, successErr := compileDefaultSecurityBundle(ctx, cfg)
	if successErr != nil {
		t.Fatalf("activate healthy candidate: %v", successErr)
	}
	candidateVersion := asString(success["version"])
	if candidateVersion == "" || candidateVersion == baselineVersion {
		t.Fatalf("candidate version=%q", candidateVersion)
	}
	rollback, rollbackErr := rollbackRulePlatformBundle(ctx, cfg, baselineVersion)
	if rollbackErr != nil {
		t.Fatalf("rollback baseline: %v", rollbackErr)
	}
	finalActive, finalActiveErr := manager.Active(ctx)
	if finalActiveErr != nil {
		t.Fatalf("load final active manifest: %v", finalActiveErr)
	}
	if finalActive.Revision != baselineVersion || finalActive.Digest != baselineManifest.Digest || runtime.state != beforeRuntime {
		t.Fatalf("rollback mismatch manifest=%#v runtime=%#v baseline=%#v", finalActive, runtime.state, baselineManifest)
	}
	if asString(rollback["rollback_from"]) != candidateVersion {
		t.Fatalf("rollback source=%q, want %q", asString(rollback["rollback_from"]), candidateVersion)
	}
	var activeVersion string
	if err := pool.QueryRow(ctx, `SELECT version FROM rule_bundles WHERE status='active'`).Scan(&activeVersion); err != nil {
		t.Fatalf("read final active database bundle: %v", err)
	}
	if activeVersion != baselineVersion {
		t.Fatalf("final active database bundle=%q", activeVersion)
	}
	var successfulEvents, rollbackEvents int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_hot_reload_events WHERE status='ok' AND bundle_version=$1`, candidateVersion).Scan(&successfulEvents); err != nil {
		t.Fatalf("count successful reload events: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_hot_reload_events WHERE status='rollback_ok' AND bundle_version=$1`, baselineVersion).Scan(&rollbackEvents); err != nil {
		t.Fatalf("count rollback events: %v", err)
	}
	if successfulEvents != 1 || rollbackEvents != 1 {
		t.Fatalf("reload events success=%d rollback=%d", successfulEvents, rollbackEvents)
	}
	if output := os.Getenv("LYFLOW_RELOAD_AUDIT_RESULT"); output != "" {
		restoredBundle, err := os.ReadFile(finalActive.BundlePath)
		if err != nil {
			t.Fatalf("read restored active bundle: %v", err)
		}
		restoredBundleOutput := filepath.Join(filepath.Dir(output), "restored-active-bundle.json")
		if err := os.WriteFile(restoredBundleOutput, restoredBundle, 0o600); err != nil {
			t.Fatalf("export restored active bundle: %v", err)
		}
		result, err := json.MarshalIndent(map[string]interface{}{
			"status": "PASS", "baseline_version": baselineVersion, "baseline_digest": baselineManifest.Digest,
			"candidate_version": candidateVersion, "failed_events": failedEvents,
			"successful_events": successfulEvents, "rollback_events": rollbackEvents,
			"final_version": finalActive.Revision, "final_digest": finalActive.Digest, "final_bundle_path": restoredBundleOutput,
		}, "", "  ")
		if err != nil {
			t.Fatalf("encode reload audit result: %v", err)
		}
		if err := os.WriteFile(output, append(result, '\n'), 0o600); err != nil {
			t.Fatalf("write reload audit result: %v", err)
		}
	}
}
