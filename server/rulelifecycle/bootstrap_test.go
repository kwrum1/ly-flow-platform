package rulelifecycle

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

func TestCompileStrict_accepts_artifact_category(t *testing.T) {
	// Given
	bundle := []byte(`{"version":"baseline-1","rules":[{"id":"artifact-1","name":"artifact rule","category":"artifact","severity":"low","field":"path","operator":"contains","value":"fixture"}]}`)

	// When
	preview, err := compileStrict(bundle, "baseline-1")

	// Then
	if err != nil {
		t.Fatalf("compile artifact rule: %v", err)
	}
	if preview.RuleCount != 1 {
		t.Fatalf("artifact rule count=%d, want 1", preview.RuleCount)
	}
}

func TestBootstrapActiveManifest_publishes_signed_baseline_without_runtime(t *testing.T) {
	// Given
	config := newBootstrapConfig(t)
	previousUmask := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	// When
	manifest, err := BootstrapActiveManifest(config)

	// Then
	if err != nil {
		t.Fatalf("bootstrap active manifest: %v", err)
	}
	if manifest.Signature == "" || manifest.Revision != "baseline-1" || manifest.Digest != sha256Hex(validBundle("baseline-1", "r1")) {
		t.Fatalf("unexpected bootstrap manifest: %#v", manifest)
	}
	assertBootstrapMode(t, config.RootDir, 0o755)
	assertBootstrapMode(t, filepath.Join(config.RootDir, "candidates"), 0o755)
	assertBootstrapMode(t, filepath.Dir(manifest.BundlePath), 0o755)
	assertBootstrapMode(t, manifest.BundlePath, 0o644)
	assertBootstrapMode(t, filepath.Join(config.RootDir, activeManifestName), 0o644)
	assertBootstrapMode(t, config.Verifier.KeyDir, 0o700)
	assertBootstrapMode(t, config.Verifier.KeyPath(trustroot.RuleSigner), 0o600)
	manager := newBootstrapVerifier(t, config)
	active, _, err := manager.loadActive()
	if err != nil {
		t.Fatalf("verify bootstrapped active manifest: %v", err)
	}
	if active != manifest {
		t.Fatalf("verified manifest=%#v, want %#v", active, manifest)
	}
}

func TestBootstrapActiveManifest_preserves_existing_valid_state(t *testing.T) {
	// Given
	config := newBootstrapConfig(t)
	if _, err := BootstrapActiveManifest(config); err != nil {
		t.Fatalf("create initial active manifest: %v", err)
	}
	activePath := filepath.Join(config.RootDir, activeManifestName)
	before, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read initial active manifest: %v", err)
	}
	config.Now = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }

	// When
	_, err = BootstrapActiveManifest(config)

	// Then
	if err != nil {
		t.Fatalf("reuse active manifest: %v", err)
	}
	after, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("read preserved active manifest: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("valid active state was rewritten")
	}
}

func TestBootstrapActiveManifest_normalizes_existing_lifecycle_tree(t *testing.T) {
	// Given
	config := newBootstrapConfig(t)
	manifest, err := BootstrapActiveManifest(config)
	if err != nil {
		t.Fatalf("create initial active manifest: %v", err)
	}
	historyDir := filepath.Join(config.RootDir, "history", "baseline-1")
	if err := os.MkdirAll(historyDir, 0o700); err != nil {
		t.Fatalf("create legacy history directory: %v", err)
	}
	historyFile := filepath.Join(historyDir, "previous.json")
	if err := os.WriteFile(historyFile, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("create legacy history file: %v", err)
	}
	if err := os.Chmod(config.RootDir, 0o700); err != nil {
		t.Fatalf("restrict lifecycle root: %v", err)
	}

	// When
	_, err = BootstrapActiveManifest(config)

	// Then
	if err != nil {
		t.Fatalf("normalize existing lifecycle tree: %v", err)
	}
	assertBootstrapMode(t, config.RootDir, 0o755)
	assertBootstrapMode(t, historyDir, 0o755)
	assertBootstrapMode(t, historyFile, 0o644)
	assertBootstrapMode(t, manifest.BundlePath, 0o644)
}

func TestBootstrapActiveManifest_serializes_concurrent_first_start(t *testing.T) {
	// Given
	config := newBootstrapConfig(t)
	results := make(chan ActiveManifest, 2)
	errors := make(chan error, 2)

	// When
	var group sync.WaitGroup
	group.Add(2)
	for range 2 {
		go func() {
			defer group.Done()
			manifest, err := BootstrapActiveManifest(config)
			if err != nil {
				errors <- err
				return
			}
			results <- manifest
		}()
	}
	group.Wait()
	close(results)
	close(errors)

	// Then
	for err := range errors {
		t.Fatalf("concurrent bootstrap: %v", err)
	}
	var manifests []ActiveManifest
	for manifest := range results {
		manifests = append(manifests, manifest)
	}
	if len(manifests) != 2 || manifests[0] != manifests[1] {
		t.Fatalf("concurrent manifests=%#v, want two identical manifests", manifests)
	}
}

func TestBootstrapActiveManifest_fails_closed_on_partial_or_tampered_state(t *testing.T) {
	t.Run("partial candidate", func(t *testing.T) {
		// Given
		config := newBootstrapConfig(t)
		candidateDir := filepath.Join(config.RootDir, "candidates", "partial")
		if err := os.MkdirAll(candidateDir, 0o755); err != nil {
			t.Fatalf("create partial candidate: %v", err)
		}
		if err := os.WriteFile(filepath.Join(candidateDir, "orphan.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatalf("write partial candidate: %v", err)
		}

		// When
		_, err := BootstrapActiveManifest(config)

		// Then
		if !errors.Is(err, ErrRevision) {
			t.Fatalf("partial state error=%v, want ErrRevision", err)
		}
	})

	t.Run("tampered active bundle", func(t *testing.T) {
		// Given
		config := newBootstrapConfig(t)
		manifest, err := BootstrapActiveManifest(config)
		if err != nil {
			t.Fatalf("create initial active manifest: %v", err)
		}
		if err := os.WriteFile(manifest.BundlePath, validBundle("baseline-1", "tampered"), 0o600); err != nil {
			t.Fatalf("tamper active bundle: %v", err)
		}

		// When
		_, err = BootstrapActiveManifest(config)

		// Then
		if !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("tampered state error=%v, want ErrDigestMismatch", err)
		}
	})
}

func newBootstrapConfig(t *testing.T) BootstrapConfig {
	t.Helper()
	base := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		t.Fatalf("ensure online roots: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.RuleSigner)
	if err != nil {
		t.Fatalf("load rule signer: %v", err)
	}
	baselinePath := filepath.Join(base, "package", "active-bundle.json")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		t.Fatalf("create package rules directory: %v", err)
	}
	if err := os.WriteFile(baselinePath, validBundle("baseline-1", "r1"), 0o644); err != nil {
		t.Fatalf("write package baseline: %v", err)
	}
	return BootstrapConfig{
		RootDir: filepath.Join(base, "lifecycle"), BaselinePath: baselinePath, Signer: signer, Verifier: layout,
		Now: func() time.Time { return time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC) },
	}
}

func newBootstrapVerifier(t *testing.T, config BootstrapConfig) *Manager {
	t.Helper()
	manager, err := NewManager(ManagerConfig{
		RootDir: config.RootDir, Signer: config.Signer, Verifier: config.Verifier, Audit: &memoryAudit{}, Runtime: &fakeRuntime{}, Now: config.Now,
	})
	if err != nil {
		t.Fatalf("create bootstrap verifier: %v", err)
	}
	return manager
}

func assertBootstrapMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat bootstrap path %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("bootstrap mode %s=%#o, want %#o", path, got, want)
	}
}
