package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ly-flow-platform/security-engine/config"
)

func TestSecurityEngineProcess_startup_and_reload_require_signed_active_lifecycle(t *testing.T) {
	// Given
	redisAddress := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	if redisAddress == "" {
		t.Skip("LYFLOW_TEST_REDIS_ADDR is required for process lifecycle QA")
	}
	root := t.TempDir()
	bundleRoot := filepath.Join(root, "rules")
	if err := os.MkdirAll(bundleRoot, 0o700); err != nil {
		t.Fatalf("create bundle root: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate rule key: %v", err)
	}
	ruleRootPath := writeRuleRoot(t, root, publicKey)
	controlToken := "process-test-control-token"
	auditPath := filepath.Join(root, "reload-audit.jsonl")
	manifestV1, digestV1 := writeProcessLifecycle(t, processLifecycleFixture{BundleRoot: bundleRoot, PrivateKey: privateKey, PublicKey: publicKey, Revision: "v1"})
	manifestV2, digestV2 := writeProcessLifecycle(t, processLifecycleFixture{BundleRoot: bundleRoot, PrivateKey: privateKey, PublicKey: publicKey, Revision: "v2"})
	address := reserveHTTPAddress(t)
	process := exec.Command(os.Args[0], "-test.run=^TestSecurityEngineProcessHelper$", "-test.v")
	process.Env = append(os.Environ(),
		"LYFLOW_SECURITY_ENGINE_PROCESS_HELPER=1",
		"REDIS_ADDR="+redisAddress,
		"SECURITY_ENGINE_HTTP_ADDR="+address,
		"SECURITY_ENGINE_LIFECYCLE_MANIFEST="+manifestV1,
		"SECURITY_ENGINE_RULE_TRUST_ROOT="+ruleRootPath,
		"SECURITY_ENGINE_BUNDLE_ROOT="+bundleRoot,
		"SECURITY_ENGINE_CONTROL_TOKEN="+controlToken,
		"SECURITY_ENGINE_RELOAD_AUDIT_PATH="+auditPath,
	)
	var processOutput bytes.Buffer
	process.Stdout = &processOutput
	process.Stderr = &processOutput
	if err := process.Start(); err != nil {
		t.Fatalf("start security-engine process: %v", err)
	}
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	client := &http.Client{Timeout: time.Second}
	healthURL := "http://" + address + "/health"
	waitForProcessHealth(t, client, processHealthExpectation{URL: healthURL, StatusCode: http.StatusOK, Revision: "v1", Digest: digestV1, PreventionEnabled: true})

	// When
	manifestV2Contents, err := os.ReadFile(manifestV2)
	if err != nil {
		t.Fatalf("read v2 manifest: %v", err)
	}
	if err := os.WriteFile(manifestV1, manifestV2Contents, 0o600); err != nil {
		t.Fatalf("activate v2 manifest: %v", err)
	}
	reloadURL := "http://" + address + "/reload"
	unauthenticatedStatus := postReload(t, client, processReloadRequest{URL: reloadURL, ManifestPath: manifestV1, Digest: digestV2})
	analystStatus := postReload(t, client, processReloadRequest{URL: reloadURL, ManifestPath: manifestV1, Digest: digestV2, Token: controlToken, Principal: "user:analyst-1", Role: "analyst"})
	validStatus := postReload(t, client, processReloadRequest{URL: reloadURL, ManifestPath: manifestV1, Digest: digestV2, Token: controlToken, Principal: "service:ly-server", Role: "admin"})
	waitForProcessHealth(t, client, processHealthExpectation{URL: healthURL, StatusCode: http.StatusOK, Revision: "v2", Digest: digestV2, PreventionEnabled: true})
	tamperProcessManifest(t, manifestV1)
	tamperedStatus := postReload(t, client, processReloadRequest{URL: reloadURL, ManifestPath: manifestV1, Digest: digestV2, Token: controlToken, Principal: "service:ly-server", Role: "admin"})

	// Then
	if unauthenticatedStatus != http.StatusUnauthorized || analystStatus != http.StatusForbidden || validStatus != http.StatusOK || tamperedStatus != http.StatusBadRequest {
		t.Fatalf("reload statuses unauth=%d analyst=%d valid=%d tampered=%d process=%s", unauthenticatedStatus, analystStatus, validStatus, tamperedStatus, processOutput.String())
	}
	waitForProcessHealth(t, client, processHealthExpectation{
		URL: healthURL, StatusCode: http.StatusServiceUnavailable, Revision: "v2", Digest: digestV2,
		Reason: "config_or_binary_integrity_failed", PreventionEnabled: false,
	})
	auditContents, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read durable reload audit: %v", err)
	}
	if !bytes.Contains(auditContents, []byte(`"result":"denied"`)) || !bytes.Contains(auditContents, []byte(`"result":"succeeded"`)) || !bytes.Contains(auditContents, []byte(`"principal":"service:ly-server"`)) {
		t.Fatalf("durable reload audit missing outcomes: %s", auditContents)
	}
}

func TestSecurityEngineProcess_rejects_startup_without_active_manifest(t *testing.T) {
	// Given
	redisAddress := os.Getenv("LYFLOW_TEST_REDIS_ADDR")
	if redisAddress == "" {
		t.Skip("LYFLOW_TEST_REDIS_ADDR is required for process lifecycle QA")
	}
	process := exec.Command(os.Args[0], "-test.run=^TestSecurityEngineProcessHelper$", "-test.v")
	process.Env = append(os.Environ(),
		"LYFLOW_SECURITY_ENGINE_PROCESS_HELPER=1",
		"REDIS_ADDR="+redisAddress,
		"SECURITY_ENGINE_HTTP_ADDR="+reserveHTTPAddress(t),
		"SECURITY_ENGINE_LIFECYCLE_MANIFEST="+filepath.Join(t.TempDir(), "missing.json"),
		"SECURITY_ENGINE_RULE_TRUST_ROOT="+filepath.Join(t.TempDir(), "missing-root.pem"),
		"SECURITY_ENGINE_BUNDLE_ROOT="+t.TempDir(),
		"SECURITY_ENGINE_CONTROL_TOKEN=process-test-control-token",
		"SECURITY_ENGINE_RELOAD_AUDIT_PATH="+filepath.Join(t.TempDir(), "reload-audit.jsonl"),
	)

	// When
	err := process.Run()

	// Then
	if err == nil {
		t.Fatal("security-engine process started without a signed active lifecycle manifest")
	}
}

func TestSecurityEngineProcessHelper(t *testing.T) {
	if os.Getenv("LYFLOW_SECURITY_ENGINE_PROCESS_HELPER") != "1" {
		t.Skip("process helper")
	}
	if err := run(context.Background(), config.Load()); err != nil {
		t.Fatalf("run security-engine helper: %v", err)
	}
}
