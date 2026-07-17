package trustroot

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRotatePreservesOverlapUntilPreviousRootIsRevoked(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap trust layout: %v", err)
	}
	oldSigner, err := layout.LoadSigner(PolicySigner)
	if err != nil {
		t.Fatalf("load old signer: %v", err)
	}
	payload := []byte("policy-v1")
	oldSignature := oldSigner.Sign(payload)
	oldFingerprint := oldSigner.Fingerprint()

	// When
	if err := layout.Rotate(PolicyRoot, rand.Reader); err != nil {
		t.Fatalf("rotate policy root: %v", err)
	}
	overlapErr := layout.Verify(PolicyRoot, payload, oldSignature)
	revokeErr := layout.Revoke(PolicyRoot, oldFingerprint)
	afterRevokeErr := layout.Verify(PolicyRoot, payload, oldSignature)

	// Then
	if overlapErr != nil {
		t.Fatalf("previous root must verify during overlap: %v", overlapErr)
	}
	if revokeErr != nil {
		t.Fatalf("revoke previous root: %v", revokeErr)
	}
	if !errors.Is(afterRevokeErr, ErrRootRevoked) {
		t.Fatalf("error=%v, want ErrRootRevoked", afterRevokeErr)
	}
}

func TestRecoverRejectsStaleRevokedRoot(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap trust layout: %v", err)
	}
	signer, err := layout.LoadSigner(AuditSigner)
	if err != nil {
		t.Fatalf("load audit signer: %v", err)
	}
	if err := layout.Revoke(AuditRoot, signer.Fingerprint()); err != nil {
		t.Fatalf("revoke audit root: %v", err)
	}
	snapshot := filepath.Join(base, "snapshot")
	if err := layout.Backup(snapshot); err != nil {
		t.Fatalf("backup trust state: %v", err)
	}

	// When
	err = layout.Recover(snapshot)

	// Then
	if !errors.Is(err, ErrRootRevoked) {
		t.Fatalf("error=%v, want ErrRootRevoked", err)
	}
}

func TestRecoverRejectsRevokedReleaseRoot(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap trust layout: %v", err)
	}
	bundleDir := filepath.Join(base, "bundle")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("create bundle directory: %v", err)
	}
	externalRoot := filepath.Join(base, "operator", "release-root.pem")
	publicKey := writePublicRoot(t, externalRoot)
	if err := layout.InstallReleaseRoot(externalRoot, bundleDir); err != nil {
		t.Fatalf("install release root: %v", err)
	}
	if err := layout.Revoke(ReleaseRoot, fingerprint(publicKey)); err != nil {
		t.Fatalf("revoke release root: %v", err)
	}
	snapshot := filepath.Join(base, "snapshot")
	if err := layout.Backup(snapshot); err != nil {
		t.Fatalf("backup trust state: %v", err)
	}

	// When
	err := layout.Recover(snapshot)

	// Then
	if !errors.Is(err, ErrRootRevoked) {
		t.Fatalf("error=%v, want ErrRootRevoked", err)
	}
}
