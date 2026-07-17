package rulelifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   bool
}

func (a *memoryAudit) Record(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("audit unavailable")
	}
	a.events = append(a.events, event)
	return nil
}

func (a *memoryAudit) contains(action, result string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, event := range a.events {
		if event.Action == action && event.Result == result {
			return true
		}
	}
	return false
}

func (a *memoryAudit) containsStage(action, result, stage string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, event := range a.events {
		if event.Action == action && event.Result == result && event.Fields["stage"] == stage {
			return true
		}
	}
	return false
}

type fakeRuntime struct {
	mu             sync.Mutex
	active         string
	activeRevision string
	activePath     string
	failHealth     bool
	reloads        []string
}

func (r *fakeRuntime) Snapshot(_ context.Context) (RuntimeState, error) {
	return r.snapshot(), nil
}

func (r *fakeRuntime) Reload(_ context.Context, manifestPath, digest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = digest
	r.activePath = manifestPath
	r.reloads = append(r.reloads, digest)
	return nil
}

func (r *fakeRuntime) Restore(_ context.Context, state RuntimeState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = state.Digest
	r.activeRevision = state.Revision
	r.activePath = state.ManifestPath
	r.reloads = append(r.reloads, state.Digest)
	return nil
}

func (r *fakeRuntime) snapshot() RuntimeState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RuntimeState{ManifestPath: r.activePath, Revision: r.activeRevision, Digest: r.active}
}

func (r *fakeRuntime) Health(_ context.Context, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failHealth {
		r.failHealth = false
		return errors.New("fixture unhealthy")
	}
	return nil
}

func (r *fakeRuntime) activeDigest() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

func TestManager_sync_preview_activate_signs_manifest_and_audits_lifecycle(t *testing.T) {
	// Given
	manager, audit, runtime := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	bundle := validBundle("rev-1", "r1")
	pin := SourcePin{URL: "https://rules.example.test/rev-1/bundle.json", Revision: "rev-1", SHA256: sha256Hex(bundle)}

	// When
	preview, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: pin, FinalURL: pin.URL, Content: bundle, verified: true})
	if err != nil {
		t.Fatalf("stage preview: %v", err)
	}
	manifest, err := manager.Activate(context.Background(), actor, "rev-1")

	// Then
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if preview.RuleCount != 1 || preview.WouldActivate || manifest.Revision != "rev-1" || manifest.Signature == "" {
		t.Fatalf("unexpected preview/manifest: %#v %#v", preview, manifest)
	}
	active, err := manager.Active(context.Background())
	if err != nil {
		t.Fatalf("read active manifest: %v", err)
	}
	if active.Digest != pin.SHA256 || runtime.activeDigest() != pin.SHA256 {
		t.Fatalf("active digest mismatch: manifest=%s runtime=%s", active.Digest, runtime.activeDigest())
	}
	for _, expected := range []string{"rule.source.parse", "rule.source.persist", "rule.compile.preview", "rule.reload", "rule.activate"} {
		if !audit.contains(expected, AuditResultSucceeded) {
			t.Fatalf("missing durable success audit for %s", expected)
		}
	}
}

func TestManager_health_failure_auto_rolls_back_active_manifest_and_runtime(t *testing.T) {
	// Given
	manager, audit, runtime := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	first := validBundle("rev-1", "r1")
	firstPin := SourcePin{URL: "https://rules.example.test/rev-1/bundle.json", Revision: "rev-1", SHA256: sha256Hex(first)}
	if _, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: firstPin, FinalURL: firstPin.URL, Content: first, verified: true}); err != nil {
		t.Fatalf("stage first: %v", err)
	}
	if _, err := manager.Activate(context.Background(), actor, "rev-1"); err != nil {
		t.Fatalf("activate first: %v", err)
	}
	second := validBundle("rev-2", "r2")
	secondPin := SourcePin{URL: "https://rules.example.test/rev-2/bundle.json", Revision: "rev-2", SHA256: sha256Hex(second)}
	if _, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: secondPin, FinalURL: secondPin.URL, Content: second, verified: true}); err != nil {
		t.Fatalf("stage second: %v", err)
	}
	runtime.mu.Lock()
	runtime.failHealth = true
	runtime.mu.Unlock()

	// When
	_, activateErr := manager.Activate(context.Background(), actor, "rev-2")
	active, activeErr := manager.Active(context.Background())

	// Then
	if !errors.Is(activateErr, ErrHealth) || activeErr != nil {
		t.Fatalf("activation errors: activate=%v active=%v", activateErr, activeErr)
	}
	if active.Revision != "rev-1" || runtime.activeDigest() != firstPin.SHA256 {
		t.Fatalf("rollback failed: active=%#v runtime=%s", active, runtime.activeDigest())
	}
	if !audit.contains("rule.rollback", AuditResultSucceeded) || !audit.contains("rule.activate", AuditResultFailed) {
		t.Fatalf("missing health rollback audit: %#v", audit.events)
	}
}

func TestManager_rejects_non_admin_and_strict_compile_failures_with_audit(t *testing.T) {
	// Given
	manager, audit, _ := newTestManager(t)
	badBundle := []byte(`{"version":"rev-bad","rules":[{"id":"r1","name":"bad","category":"runtime","severity":"low","field":"message","operator":"contains","value":"x","script":"system('id')"}]}`)
	bad := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/rev-bad/bundle.json", Revision: "rev-bad", SHA256: sha256Hex(badBundle)}, Content: badBundle, verified: true}

	// When
	_, deniedErr := manager.StagePreview(context.Background(), Actor{ID: "analyst-1", Role: RoleAnalyst}, bad)
	_, compileErr := manager.StagePreview(context.Background(), Actor{ID: "admin-1", Role: RoleAdmin}, bad)

	// Then
	if !errors.Is(deniedErr, ErrForbidden) || !errors.Is(compileErr, ErrCompile) {
		t.Fatalf("errors denied=%v compile=%v", deniedErr, compileErr)
	}
	if !audit.contains("rule.source.sync", AuditResultDenied) || !audit.contains("rule.compile.preview", AuditResultFailed) {
		t.Fatalf("missing denial/compile audit: %#v", audit.events)
	}
}

func TestManager_fails_closed_when_durable_audit_is_unavailable(t *testing.T) {
	// Given
	manager, audit, runtime := newTestManager(t)
	audit.fail = true
	bundle := validBundle("rev-1", "r1")
	source := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/rev-1/bundle.json", Revision: "rev-1", SHA256: sha256Hex(bundle)}, Content: bundle, verified: true}

	// When
	_, err := manager.StagePreview(context.Background(), Actor{ID: "admin-1", Role: RoleAdmin}, source)

	// Then
	if !errors.Is(err, ErrAudit) || runtime.activeDigest() != "" {
		t.Fatalf("audit failure did not fail closed: err=%v runtime=%s", err, runtime.activeDigest())
	}
}

func TestManager_manual_reload_and_rollback_are_authorized_audited_and_healthy(t *testing.T) {
	// Given
	manager, audit, runtime := newTestManager(t)
	admin := Actor{ID: "admin-1", Role: RoleAdmin}
	for _, revision := range []string{"rev-1", "rev-2"} {
		bundle := validBundle(revision, revision+"-rule")
		source := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/" + revision, Revision: revision, SHA256: sha256Hex(bundle)}, Content: bundle, verified: true}
		if _, err := manager.StagePreview(context.Background(), admin, source); err != nil {
			t.Fatalf("stage %s: %v", revision, err)
		}
		if _, err := manager.Activate(context.Background(), admin, revision); err != nil {
			t.Fatalf("activate %s: %v", revision, err)
		}
	}

	// When
	deniedErr := manager.Reload(context.Background(), Actor{ID: "analyst-1", Role: RoleAnalyst})
	reloadErr := manager.Reload(context.Background(), admin)
	rolledBack, rollbackErr := manager.Rollback(context.Background(), admin, "rev-1")

	// Then
	if !errors.Is(deniedErr, ErrForbidden) || reloadErr != nil || rollbackErr != nil {
		t.Fatalf("reload/rollback errors: denied=%v reload=%v rollback=%v", deniedErr, reloadErr, rollbackErr)
	}
	if rolledBack.Revision != "rev-1" || runtime.activeDigest() != rolledBack.Digest {
		t.Fatalf("manual rollback mismatch: manifest=%#v runtime=%s", rolledBack, runtime.activeDigest())
	}
	if !audit.contains("rule.reload", AuditResultDenied) || !audit.contains("rule.rollback", AuditResultSucceeded) {
		t.Fatalf("reload/rollback audit missing: %#v", audit.events)
	}
}

func TestManager_same_revision_rejects_different_digest(t *testing.T) {
	// Given
	manager, _, _ := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	first := validBundle("rev-1", "r1")
	firstSource := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/rev-1", Revision: "rev-1", SHA256: sha256Hex(first)}, Content: first, verified: true}
	if _, err := manager.StagePreview(context.Background(), actor, firstSource); err != nil {
		t.Fatalf("stage first revision: %v", err)
	}
	replacement := validBundle("rev-1", "r2")
	replacementSource := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/rev-1", Revision: "rev-1", SHA256: sha256Hex(replacement)}, Content: replacement, verified: true}

	// When
	_, err := manager.StagePreview(context.Background(), actor, replacementSource)

	// Then
	if !errors.Is(err, ErrRevision) {
		t.Fatalf("replacement error = %v, want ErrRevision", err)
	}
}

func newTestManager(t *testing.T) (*Manager, *memoryAudit, *fakeRuntime) {
	t.Helper()
	base := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		t.Fatalf("ensure roots: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.RuleSigner)
	if err != nil {
		t.Fatalf("load rule signer: %v", err)
	}
	audit := &memoryAudit{}
	runtime := &fakeRuntime{}
	manager, err := NewManager(ManagerConfig{RootDir: filepath.Join(base, "rules"), Signer: signer, Verifier: layout, Audit: audit, Runtime: runtime, Now: func() time.Time { return time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(filepath.Join(base, "rules")); err != nil {
			t.Errorf("cleanup rules: %v", err)
		}
	})
	return manager, audit, runtime
}

func validBundle(revision, ruleID string) []byte {
	return []byte(`{"version":"` + revision + `","rules":[{"id":"` + ruleID + `","name":"benign","category":"runtime","severity":"low","field":"message","operator":"contains","value":"fixture"}]}`)
}
