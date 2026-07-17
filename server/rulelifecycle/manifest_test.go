package rulelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManager_active_rejects_tampered_signed_manifest(t *testing.T) {
	// Given
	manager, _, _ := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	bundle := validBundle("rev-1", "r1")
	source := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/rev-1/bundle.json", Revision: "rev-1", SHA256: sha256Hex(bundle)}, Content: bundle, verified: true}
	if _, err := manager.StagePreview(context.Background(), actor, source); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := manager.Activate(context.Background(), actor, "rev-1"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	path := filepath.Join(manager.rootDir, activeManifestName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest ActiveManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tampered, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal tampered manifest: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered manifest: %v", err)
	}

	// When
	_, activeErr := manager.Active(context.Background())

	// Then
	if !errors.Is(activeErr, ErrManifestSignature) {
		t.Fatalf("tampered manifest error = %v, want ErrManifestSignature", activeErr)
	}
}

func TestManager_active_rejects_signed_manifest_when_source_revision_differs(t *testing.T) {
	// Given
	manager, _, _ := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	bundle := validBundle("rev-1", "r1")
	source := FetchedSource{Pin: SourcePin{URL: "https://rules.example.test/rev-1/bundle.json", Revision: "rev-1", SHA256: sha256Hex(bundle)}, Content: bundle, verified: true}
	if _, err := manager.StagePreview(context.Background(), actor, source); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, err := manager.Activate(context.Background(), actor, "rev-1"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	path := filepath.Join(manager.rootDir, activeManifestName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest ActiveManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.SourceRevision = "upstream-rev-2"
	manifest, err = signManifest(manifest, manager.signer)
	if err != nil {
		t.Fatalf("sign mismatched manifest: %v", err)
	}
	contents, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal mismatched manifest: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write mismatched manifest: %v", err)
	}

	// When
	_, activeErr := manager.Active(context.Background())

	// Then
	if !errors.Is(activeErr, ErrRevision) {
		t.Fatalf("source revision mismatch error = %v, want ErrRevision", activeErr)
	}
}
