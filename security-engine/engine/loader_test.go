package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadLifecycleBundle_requires_verified_signed_active_manifest_and_digest(t *testing.T) {
	// Given
	manifestPath, rootPath, bundleRoot, digest := writeSignedLifecycleFixture(t)

	// When
	bundle, loaded, err := LoadLifecycleBundle(manifestPath, rootPath, bundleRoot)

	// Then
	if err != nil {
		t.Fatalf("load signed lifecycle bundle: %v", err)
	}
	if bundle.Version != "v1" || bundle.Digest != digest || loaded.ManifestPath != manifestPath {
		t.Fatalf("unexpected verified bundle: bundle=%#v manifest=%#v", bundle, loaded)
	}
}

func TestLoadLifecycleBundle_rejects_manifest_tamper_and_unpinned_bundle(t *testing.T) {
	// Given
	manifestPath, rootPath, bundleRoot, _ := writeSignedLifecycleFixture(t)
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest lifecycleManifestFixture
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.Revision = "v2"
	tampered, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal tampered manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered manifest: %v", err)
	}

	// When
	_, _, loadErr := LoadLifecycleBundle(manifestPath, rootPath, bundleRoot)

	// Then
	if !errors.Is(loadErr, ErrLifecycleManifest) {
		t.Fatalf("tampered manifest error = %v, want ErrLifecycleManifest", loadErr)
	}
}

func TestLoadLifecycleBundle_rejects_signed_source_revision_mismatch(t *testing.T) {
	// Given
	manifestPath, rootPath, bundleRoot, _ := writeSignedLifecycleFixtureWithSourceRevision(t, "upstream-v2")

	// When
	_, _, err := LoadLifecycleBundle(manifestPath, rootPath, bundleRoot)

	// Then
	if !errors.Is(err, ErrLifecycleManifest) {
		t.Fatalf("source revision mismatch error = %v, want ErrLifecycleManifest", err)
	}
}

type lifecycleManifestFixture struct {
	SchemaVersion     string    `json:"schema_version"`
	Revision          string    `json:"revision"`
	Digest            string    `json:"digest"`
	BundlePath        string    `json:"bundle_path"`
	SourceURL         string    `json:"source_url"`
	SourceRevision    string    `json:"source_revision"`
	ActivatedAt       time.Time `json:"activated_at"`
	PreviousRevision  string    `json:"previous_revision,omitempty"`
	SignerFingerprint string    `json:"signer_fingerprint"`
	Signature         string    `json:"signature"`
}

func writeSignedLifecycleFixture(t *testing.T) (string, string, string, string) {
	return writeSignedLifecycleFixtureWithSourceRevision(t, "v1")
}

func writeSignedLifecycleFixtureWithSourceRevision(t *testing.T, sourceRevision string) (string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	bundleRoot := filepath.Join(root, "rules")
	if err := os.MkdirAll(bundleRoot, 0o700); err != nil {
		t.Fatalf("create bundle root: %v", err)
	}
	bundlePath := filepath.Join(bundleRoot, "bundle.json")
	bundle := []byte(`{"version":"v1","rules":[{"id":"r1","name":"Runtime","category":"runtime","severity":"high","score_hint":80,"field":"cmd","value":"/dev/tcp"}]}`)
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	digestBytes := sha256.Sum256(bundle)
	digest := hex.EncodeToString(digestBytes[:])
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	rootPath := filepath.Join(root, "rule-root.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	fingerprint := sha256.Sum256(publicKey)
	manifest := lifecycleManifestFixture{
		SchemaVersion: "lyflow.rule-manifest/v1", Revision: "v1", Digest: digest,
		BundlePath: bundlePath, SourceURL: "local://fixture", SourceRevision: sourceRevision,
		ActivatedAt: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC), SignerFingerprint: hex.EncodeToString(fingerprint[:]),
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal unsigned manifest: %v", err)
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(privateKey, payload))
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal signed manifest: %v", err)
	}
	manifestPath := filepath.Join(root, "active-manifest.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return manifestPath, rootPath, bundleRoot, digest
}
