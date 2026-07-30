package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lyflow/ly-flow-platform/server/controlaudit"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type ruleSyncRuntime struct {
	mu         sync.Mutex
	state      rulelifecycle.RuntimeState
	failHealth bool
}

type failingRuleVersionStatus struct {
	err error
}

func (s failingRuleVersionStatus) MarkSynced(context.Context, string, string, string) error {
	return s.err
}

func (r *ruleSyncRuntime) Snapshot(_ context.Context) (rulelifecycle.RuntimeState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state, nil
}

func (r *ruleSyncRuntime) Reload(_ context.Context, manifestPath, digest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state.ManifestPath = manifestPath
	r.state.Digest = digest
	return nil
}

func (r *ruleSyncRuntime) Restore(_ context.Context, state rulelifecycle.RuntimeState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = state
	return nil
}

func (r *ruleSyncRuntime) Health(_ context.Context, revision, digest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failHealth {
		return errors.New("injected runtime health failure")
	}
	if r.state.Digest != digest {
		return errors.New("runtime digest mismatch")
	}
	r.state.Revision = revision
	return nil
}

func TestRulePlatformInlineSync_realPostgres_is_pinned_immutable_audited_and_activated(t *testing.T) {
	// Given
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for real rule lifecycle QA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, auth.UserContextKey, int64(1))
	ctx = context.WithValue(ctx, auth.RoleContextKey, auth.RoleAdmin)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS rule_hot_reload_events,rule_bundles,detection_rules,rule_source_versions,rule_sources CASCADE`); err != nil {
		t.Fatalf("reset rule tables: %v", err)
	}
	if err := ensureRuntimeSchema(ctx, pool); err != nil {
		t.Fatalf("apply runtime schema: %v", err)
	}
	root := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(root, "trust"), KeyDir: filepath.Join(root, "keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		t.Fatalf("ensure roots: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.RuleSigner)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	auditSigner, err := layout.LoadSigner(trustroot.AuditSigner)
	if err != nil {
		t.Fatalf("load audit signer: %v", err)
	}
	auditRootPEM, err := os.ReadFile(layout.RootPath(trustroot.AuditRoot))
	if err != nil {
		t.Fatalf("read audit root: %v", err)
	}
	auditRoot, err := trustroot.ParsePublicRoot(auditRootPEM)
	if err != nil {
		t.Fatalf("parse audit root: %v", err)
	}
	ledger, err := controlaudit.NewLedger(controlaudit.Config{
		Dir: filepath.Join(root, "audit"), Sign: auditSigner.Sign, PublicKey: auditRoot,
		Now: func() time.Time { return time.Date(2026, 7, 15, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("new audit ledger: %v", err)
	}
	runtime := &ruleSyncRuntime{state: rulelifecycle.RuntimeState{ManifestPath: "/runtime/bootstrap.json", Revision: "bootstrap", Digest: strings.Repeat("b", 64)}}
	manager, err := rulelifecycle.NewManager(rulelifecycle.ManagerConfig{
		RootDir: filepath.Join(root, "lifecycle"), Signer: signer, Verifier: layout,
		Audit: rulelifecycle.NewLedgerAudit(ledger), Runtime: runtime, Now: func() time.Time { return time.Date(2026, 7, 15, 1, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	cfg := &Config{DBPool: pool, RuleLifecycle: manager, RuleDownloadRestrictedShown: true}
	if _, err := upsertRulePlatformSource(ctx, cfg, map[string]interface{}{
		"id": "local-inline-source", "name": "Local Inline Source", "category": "rasp", "origin": "user_provided", "url": "",
	}); err != nil {
		t.Fatalf("upsert local source without URL: %v", err)
	}
	content := `SecRule ARGS "@rx union\\s+select" "id:'942100',phase:2,deny,msg:'SQL injection',severity:'CRITICAL'"`
	digestBytes := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(digestBytes[:])
	request := map[string]interface{}{"source_id": "owasp-crs-connector", "version": "v1", "content": content, "sha256": digest}
	badDigestRequest := map[string]interface{}{"source_id": "owasp-crs-connector", "version": "digest-failure", "content": content, "sha256": strings.Repeat("a", 64)}
	malformed := "secret malformed inline payload"
	parseFailureRequest := map[string]interface{}{"source_id": "owasp-crs-connector", "version": "parse-failure", "content": malformed, "sha256": sha256String(malformed)}

	// When
	_, digestErr := syncRulePlatformSource(ctx, cfg, badDigestRequest)
	_, parseErr := syncRulePlatformSource(ctx, cfg, parseFailureRequest)
	result, syncErr := syncRulePlatformSource(ctx, cfg, request)
	conflictRequest := map[string]interface{}{"source_id": "owasp-crs-connector", "version": "v1", "content": content + "\n# changed", "sha256": sha256String(content + "\n# changed")}
	_, conflictErr := syncRulePlatformSource(ctx, cfg, conflictRequest)

	// Then
	if syncErr != nil {
		t.Fatalf("inline sync: %v", syncErr)
	}
	if !errors.Is(digestErr, rulelifecycle.ErrDigestMismatch) || parseErr == nil {
		t.Fatalf("early inline failures: digest=%v parse=%v", digestErr, parseErr)
	}
	if !errors.Is(conflictErr, rulelifecycle.ErrRevision) {
		t.Fatalf("conflicting immutable revision error = %v", conflictErr)
	}
	manifest, err := manager.Active(ctx)
	if err != nil {
		t.Fatalf("load active manifest: %v", err)
	}
	if manifest.Digest == "" || manifest.Revision != "owasp-crs-connector-v1" {
		t.Fatalf("inline sync did not activate signed lifecycle: %#v", manifest)
	}
	previousRuntime := runtime.state
	injected := errors.New("injected rule version status update failure")
	cfg.RuleVersionStatus = failingRuleVersionStatus{err: injected}
	failedContent := content + "\n# v2"
	failedRequest := map[string]interface{}{"source_id": "owasp-crs-connector", "version": "v2", "content": failedContent, "sha256": sha256String(failedContent)}
	_, failedSyncErr := syncRulePlatformSource(ctx, cfg, failedRequest)
	if !errors.Is(failedSyncErr, injected) {
		t.Fatalf("injected status failure = %v, want injected error", failedSyncErr)
	}
	activeAfterFailure, err := manager.Active(ctx)
	if err != nil {
		t.Fatalf("load active manifest after compensated failure: %v", err)
	}
	if activeAfterFailure.Revision != manifest.Revision || runtime.state != previousRuntime {
		t.Fatalf("post-activation failure was not compensated: active=%#v runtime=%#v want=%#v", activeAfterFailure, runtime.state, previousRuntime)
	}
	var failedStatus string
	if err := pool.QueryRow(ctx, `SELECT sync_status FROM rule_source_versions WHERE source_id='owasp-crs-connector' AND version='v2'`).Scan(&failedStatus); err != nil {
		t.Fatalf("load failed version status: %v", err)
	}
	if failedStatus != "staged" {
		t.Fatalf("failed version status = %q, want staged", failedStatus)
	}
	snapshotPath := asString(result["snapshot_path"])
	if !strings.Contains(snapshotPath, digest) {
		t.Fatalf("snapshot path is not content-addressed: %s", snapshotPath)
	}
	var storedDigest string
	if err := pool.QueryRow(ctx, `SELECT content_hash FROM rule_source_versions WHERE source_id='owasp-crs-connector' AND version='v1'`).Scan(&storedDigest); err != nil {
		t.Fatalf("load immutable revision: %v", err)
	}
	if storedDigest != digest {
		t.Fatalf("stored digest=%s, want %s", storedDigest, digest)
	}
	auditEntries, err := ledger.Query(ctx, controlaudit.QueryAdmin)
	if err != nil {
		t.Fatalf("query verified audit ledger: %v", err)
	}
	for _, action := range []string{"rule.source.upsert", "rule.source.inline", "rule.source.parse", "rule.source.persist", "rule.activate", "rule.source.sync"} {
		found := false
		for _, event := range auditEntries {
			if event.Action == action && event.Result == rulelifecycle.AuditResultSucceeded {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing durable audit %s: %#v", action, auditEntries)
		}
	}
	for _, stage := range []string{"digest", "parse", "conflict", "persistence"} {
		found := false
		for _, event := range auditEntries {
			if event.Action == "rule.source.inline.outcome" && event.Result == rulelifecycle.AuditResultFailed && event.Fields["stage"] == stage {
				found = true
				if encoded, marshalErr := json.Marshal(event.Fields); marshalErr != nil || strings.Contains(string(encoded), malformed) {
					t.Fatalf("inline failure audit leaked content: %s err=%v", encoded, marshalErr)
				}
				break
			}
		}
		if !found {
			t.Fatalf("missing durable inline failure stage %s: %#v", stage, auditEntries)
		}
	}
}

func sha256String(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
