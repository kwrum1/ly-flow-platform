package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type processManifest struct {
	SchemaVersion     string    `json:"schema_version"`
	Revision          string    `json:"revision"`
	Digest            string    `json:"digest"`
	BundlePath        string    `json:"bundle_path"`
	SourceURL         string    `json:"source_url"`
	SourceRevision    string    `json:"source_revision"`
	ActivatedAt       time.Time `json:"activated_at"`
	SignerFingerprint string    `json:"signer_fingerprint"`
	Signature         string    `json:"signature"`
}

type processHealthExpectation struct {
	URL               string
	StatusCode        int
	Revision          string
	Digest            string
	Reason            string
	PreventionEnabled bool
}

type processReloadRequest struct {
	URL          string
	ManifestPath string
	Digest       string
	Token        string
	Principal    string
	Role         string
}

type processLifecycleFixture struct {
	BundleRoot string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Revision   string
}

func writeRuleRoot(t *testing.T, root string, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	path := filepath.Join(root, "rule-root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write rule root: %v", err)
	}
	return path
}

func writeProcessLifecycle(t *testing.T, fixture processLifecycleFixture) (string, string) {
	t.Helper()
	bundlePath := filepath.Join(fixture.BundleRoot, fixture.Revision+".json")
	bundle := []byte(fmt.Sprintf(`{"version":%q,"rules":[{"id":%q,"name":"fixture","category":"runtime","severity":"low","field":"message","value":"fixture"}]}`, fixture.Revision, fixture.Revision+"-rule"))
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatalf("write process bundle: %v", err)
	}
	digestBytes := sha256.Sum256(bundle)
	fingerprint := sha256.Sum256(fixture.PublicKey)
	manifest := processManifest{
		SchemaVersion: "lyflow.rule-manifest/v1", Revision: fixture.Revision, Digest: hex.EncodeToString(digestBytes[:]),
		BundlePath: bundlePath, SourceURL: "local://process-test", SourceRevision: fixture.Revision,
		ActivatedAt: time.Date(2026, 7, 15, 2, 0, 0, 0, time.UTC), SignerFingerprint: hex.EncodeToString(fingerprint[:]),
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal process manifest: %v", err)
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(fixture.PrivateKey, payload))
	contents, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal signed process manifest: %v", err)
	}
	manifestPath := filepath.Join(fixture.BundleRoot, fixture.Revision+"-manifest.json")
	if err := os.WriteFile(manifestPath, contents, 0o600); err != nil {
		t.Fatalf("write process manifest: %v", err)
	}
	return manifestPath, manifest.Digest
}

func reserveHTTPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve HTTP address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release HTTP address: %v", err)
	}
	return address
}

func waitForProcessHealth(t *testing.T, client *http.Client, expectation processHealthExpectation) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("security-engine did not report expected health for bundle %s", expectation.Revision)
		case <-ticker.C:
			response, err := client.Get(expectation.URL)
			if err != nil {
				continue
			}
			var health struct {
				Version       string `json:"bundle_version"`
				Digest        string `json:"bundle_digest"`
				ControlHealth struct {
					Reason            string `json:"reason"`
					PreventionEnabled bool   `json:"prevention_enabled"`
				} `json:"control_health"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&health)
			_ = response.Body.Close()
			if decodeErr == nil && response.StatusCode == expectation.StatusCode && health.Version == expectation.Revision && health.Digest == expectation.Digest && health.ControlHealth.Reason == expectation.Reason && health.ControlHealth.PreventionEnabled == expectation.PreventionEnabled {
				return
			}
		}
	}
}

func postReload(t *testing.T, client *http.Client, reload processReloadRequest) int {
	t.Helper()
	body, err := json.Marshal(map[string]string{"manifest_path": reload.ManifestPath, "sha256": reload.Digest})
	if err != nil {
		t.Fatalf("marshal reload request: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, reload.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create reload request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if reload.Token != "" {
		request.Header.Set("Authorization", "Bearer "+reload.Token)
	}
	request.Header.Set("X-Lyflow-Control-Principal", reload.Principal)
	request.Header.Set("X-Lyflow-Control-Role", reload.Role)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("post reload: %v", err)
	}
	defer response.Body.Close()
	return response.StatusCode
}

func tamperProcessManifest(t *testing.T, sourcePath string) {
	t.Helper()
	contents, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read process manifest: %v", err)
	}
	var manifest processManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode process manifest: %v", err)
	}
	manifest.Signature = strings.Repeat("0", ed25519.SignatureSize*2)
	tampered, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal tampered process manifest: %v", err)
	}
	if err := os.WriteFile(sourcePath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered process manifest: %v", err)
	}
}
