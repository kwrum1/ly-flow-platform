package trustroot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapCreatesSeparatedRootsAndOnlineKeys(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "etc", "trust"), KeyDir: filepath.Join(base, "var", "keys")}

	// When
	err := layout.Bootstrap(rand.Reader)

	// Then
	if err != nil {
		t.Fatalf("bootstrap trust layout: %v", err)
	}
	for _, role := range []RootRole{PolicyRoot, AuditRoot, RuleRoot} {
		assertFileMode(t, layout.RootPath(role), 0o644)
		keyRole, err := role.OnlineKeyRole()
		if err != nil {
			t.Fatalf("online key role for %s: %v", role, err)
		}
		assertFileMode(t, layout.KeyPath(keyRole), 0o600)
	}
	assertFileMode(t, layout.KeyDir, 0o700)
	if _, err := os.Stat(layout.RootPath(ReleaseRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("release root must be externally installed, stat error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(layout.KeyDir, "release-signer.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("online release private key must not exist, stat error=%v", err)
	}
}

func TestBootstrapUsesDistinctSignerMaterialForEveryOnlineRole(t *testing.T) {
	// Given
	base := t.TempDir()
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap trust layout: %v", err)
	}

	// When
	policy, err := os.ReadFile(layout.RootPath(PolicyRoot))
	if err != nil {
		t.Fatalf("read policy root: %v", err)
	}
	audit, err := os.ReadFile(layout.RootPath(AuditRoot))
	if err != nil {
		t.Fatalf("read audit root: %v", err)
	}
	rule, err := os.ReadFile(layout.RootPath(RuleRoot))
	if err != nil {
		t.Fatalf("read rule root: %v", err)
	}

	// Then
	if bytes.Equal(policy, audit) || bytes.Equal(policy, rule) || bytes.Equal(audit, rule) {
		t.Fatal("online signing roles must use distinct key material")
	}
}

func TestInstallReleaseRootRejectsBundleSelfTrust(t *testing.T) {
	// Given
	base := t.TempDir()
	bundleDir := filepath.Join(base, "bundle")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("create bundle directory: %v", err)
	}
	bundleRoot := filepath.Join(bundleDir, "release-root.pem")
	writePublicRoot(t, bundleRoot)
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}

	// When
	err := layout.InstallReleaseRoot(bundleRoot, bundleDir)

	// Then
	if !errors.Is(err, ErrBundleSelfTrust) {
		t.Fatalf("error=%v, want ErrBundleSelfTrust", err)
	}
	if _, err := os.Stat(layout.RootPath(ReleaseRoot)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected bundle root must not be installed, stat error=%v", err)
	}
}

func TestInstallReleaseRootAcceptsExternalPublicRoot(t *testing.T) {
	// Given
	base := t.TempDir()
	bundleDir := filepath.Join(base, "bundle")
	externalRoot := filepath.Join(base, "operator", "release-root.pem")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatalf("create bundle directory: %v", err)
	}
	writePublicRoot(t, externalRoot)
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}

	// When
	err := layout.InstallReleaseRoot(externalRoot, bundleDir)

	// Then
	if err != nil {
		t.Fatalf("install external release root: %v", err)
	}
	assertFileMode(t, layout.RootPath(ReleaseRoot), 0o644)
}

func TestInstallReleaseRootRejectsExternalSymlinkToBundleRoot(t *testing.T) {
	// Given
	base := t.TempDir()
	bundleDir := filepath.Join(base, "bundle")
	bundleRoot := filepath.Join(bundleDir, "release-root.pem")
	externalLink := filepath.Join(base, "operator", "release-root.pem")
	writePublicRoot(t, bundleRoot)
	if err := os.MkdirAll(filepath.Dir(externalLink), 0o755); err != nil {
		t.Fatalf("create operator directory: %v", err)
	}
	if err := os.Symlink(bundleRoot, externalLink); err != nil {
		t.Fatalf("create external root symlink: %v", err)
	}
	layout := Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}

	// When
	err := layout.InstallReleaseRoot(externalLink, bundleDir)

	// Then
	if !errors.Is(err, ErrBundleSelfTrust) {
		t.Fatalf("error=%v, want ErrBundleSelfTrust", err)
	}
}

func TestParsePublicRootRejectsMalformedPEM(t *testing.T) {
	// Given
	malformed := []byte("not a public root")

	// When
	_, err := ParsePublicRoot(malformed)

	// Then
	if !errors.Is(err, ErrMalformedRoot) {
		t.Fatalf("error=%v, want ErrMalformedRoot", err)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s=%#o, want %#o", path, got, want)
	}
}

func writePublicRoot(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate public root: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public root: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create public root directory: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write public root: %v", err)
	}
	return publicKey
}
