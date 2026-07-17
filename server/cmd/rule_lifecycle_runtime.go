package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/controlaudit"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type ruleRuntimeHTTP struct {
	client    *http.Client
	reloadURL string
	healthURL string
	token     string
}

func newRuleLifecycleRuntime(ctx context.Context, reloadURL string) (*rulelifecycle.Manager, error) {
	layout := trustroot.Layout{TrustDir: getEnv("POLICY_TRUST_DIR", "/etc/lyflow/trust"), KeyDir: getEnv("POLICY_KEY_DIR", "/var/lib/lyflow/keys")}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		return nil, fmt.Errorf("initialize rule trust roots: %w", err)
	}
	ruleSigner, err := layout.LoadSigner(trustroot.RuleSigner)
	if err != nil {
		return nil, fmt.Errorf("load rule signer: %w", err)
	}
	auditSigner, err := layout.LoadSigner(trustroot.AuditSigner)
	if err != nil {
		return nil, fmt.Errorf("load audit signer: %w", err)
	}
	auditRootPEM, err := os.ReadFile(layout.RootPath(trustroot.AuditRoot))
	if err != nil {
		return nil, fmt.Errorf("read audit root: %w", err)
	}
	auditRoot, err := trustroot.ParsePublicRoot(auditRootPEM)
	if err != nil {
		return nil, fmt.Errorf("parse audit root: %w", err)
	}
	ledger, err := controlaudit.NewLedger(controlaudit.Config{Dir: getEnv("CONTROL_AUDIT_DIR", controlaudit.DefaultAnchorDir), Sign: auditSigner.Sign, PublicKey: auditRoot, Now: time.Now})
	if err != nil {
		return nil, fmt.Errorf("initialize rule audit ledger: %w", err)
	}
	timeout := time.Duration(toInt(getEnv("RULE_SOURCE_TIMEOUT_SECONDS", "30"))) * time.Second
	fetcher, err := rulelifecycle.NewFetcher(rulelifecycle.FetchPolicy{
		AllowedSchemes: []string{"https"},
		AllowedDomains: splitRuleAllowlist(getEnv("RULE_SOURCE_ALLOWED_DOMAINS", defaultRuleSourceDomains)),
		MaxBytes:       int64(toInt(getEnv("RULE_SOURCE_MAX_MIB", "64"))) << 20,
		Timeout:        timeout,
		MaxRedirects:   toInt(getEnv("RULE_SOURCE_MAX_REDIRECTS", "4")),
	}, nil, nil)
	if err != nil {
		return nil, err
	}
	healthURL, err := ruleHealthURL(reloadURL)
	if err != nil {
		return nil, err
	}
	runtime := &ruleRuntimeHTTP{
		client:    &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		reloadURL: reloadURL,
		healthURL: getEnv("SECURITY_ENGINE_HEALTH_URL", healthURL),
		token:     firstNonEmpty(getEnv("SECURITY_ENGINE_CONTROL_TOKEN", ""), getEnv("REDIS_ACL_PASSWORD", ""), getEnv("REDIS_PASSWORD", "")),
	}
	if runtime.token == "" {
		return nil, errors.New("security engine control token is required")
	}
	manager, err := rulelifecycle.NewManager(rulelifecycle.ManagerConfig{
		RootDir: getEnv("RULE_LIFECYCLE_DIR", "rules/security-engine/lifecycle"), Signer: ruleSigner, Verifier: layout,
		Audit: rulelifecycle.NewLedgerAudit(ledger), Runtime: runtime, Fetcher: fetcher, Now: time.Now,
	})
	if err != nil {
		return nil, err
	}
	if _, err := manager.Active(ctx); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("verify active rule manifest: %w", err)
	}
	return manager, nil
}

func (r *ruleRuntimeHTTP) Snapshot(ctx context.Context) (rulelifecycle.RuntimeState, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.healthURL, nil)
	if err != nil {
		return rulelifecycle.RuntimeState{}, fmt.Errorf("create runtime snapshot request: %w", err)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return rulelifecycle.RuntimeState{}, fmt.Errorf("query runtime snapshot: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return rulelifecycle.RuntimeState{}, fmt.Errorf("runtime snapshot returned %s", response.Status)
	}
	var health struct {
		Status        string `json:"status"`
		BundleVersion string `json:"bundle_version"`
		BundleDigest  string `json:"bundle_digest"`
		ManifestPath  string `json:"manifest_path"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&health); err != nil {
		return rulelifecycle.RuntimeState{}, fmt.Errorf("decode runtime snapshot: %w", err)
	}
	if health.Status != "running" || health.BundleVersion == "" || health.BundleDigest == "" || health.ManifestPath == "" {
		return rulelifecycle.RuntimeState{}, errors.New("runtime snapshot is incomplete")
	}
	return rulelifecycle.RuntimeState{ManifestPath: health.ManifestPath, Revision: health.BundleVersion, Digest: health.BundleDigest}, nil
}

func (r *ruleRuntimeHTTP) Reload(ctx context.Context, manifestPath, digest string) error {
	enginePath := manifestPath
	if strings.HasPrefix(enginePath, "rules/") {
		enginePath = "/app/rules/" + strings.TrimPrefix(enginePath, "rules/")
	}
	body, err := json.Marshal(struct {
		ManifestPath string `json:"manifest_path"`
		SHA256       string `json:"sha256"`
	}{ManifestPath: enginePath, SHA256: digest})
	if err != nil {
		return fmt.Errorf("marshal reload request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.reloadURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create reload request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+r.token)
	request.Header.Set("X-Lyflow-Control-Principal", "service:ly-server")
	request.Header.Set("X-Lyflow-Control-Role", "admin")
	response, err := r.client.Do(request)
	if err != nil {
		return fmt.Errorf("reload rule runtime: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("reload rule runtime returned %s", response.Status)
	}
	return nil
}

func (r *ruleRuntimeHTTP) Restore(ctx context.Context, state rulelifecycle.RuntimeState) error {
	if err := r.Reload(ctx, state.ManifestPath, state.Digest); err != nil {
		return fmt.Errorf("restore runtime reload: %w", err)
	}
	if err := r.Health(ctx, state.Revision, state.Digest); err != nil {
		return fmt.Errorf("restore runtime health: %w", err)
	}
	return nil
}

func (r *ruleRuntimeHTTP) Health(ctx context.Context, revision, digest string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.healthURL, nil)
	if err != nil {
		return fmt.Errorf("create rule health request: %w", err)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return fmt.Errorf("query rule runtime health: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("rule runtime health returned %s", response.Status)
	}
	var health struct {
		Status        string `json:"status"`
		BundleVersion string `json:"bundle_version"`
		BundleDigest  string `json:"bundle_digest"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&health); err != nil {
		return fmt.Errorf("decode rule runtime health: %w", err)
	}
	if health.Status != "running" || health.BundleVersion != revision || health.BundleDigest != digest {
		return fmt.Errorf("rule runtime unhealthy: status=%s bundle=%s digest=%s", health.Status, health.BundleVersion, health.BundleDigest)
	}
	return nil
}

func ruleLifecycleActor(ctx context.Context) rulelifecycle.Actor {
	return rulelifecycle.Actor{ID: fmt.Sprintf("user:%d", auth.GetUserIDFromContext(ctx)), Role: rulelifecycle.Role(auth.GetRoleFromContext(ctx))}
}

func ruleHealthURL(reloadURL string) (string, error) {
	parsed, err := url.Parse(reloadURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("invalid security engine reload URL")
	}
	parsed.Path = "/health"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func splitRuleAllowlist(raw string) []string {
	items := strings.Split(raw, ",")
	allowed := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			allowed = append(allowed, item)
		}
	}
	return allowed
}

const defaultRuleSourceDomains = "raw.githubusercontent.com,rules.emergingthreats.net,openinfosecfoundation.org,ti.stamus-networks.io,www.snort.org,rules.ptsecurity.com"
