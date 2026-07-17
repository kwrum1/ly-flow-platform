package rulelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManager_first_activation_health_failure_restores_preexisting_runtime_without_manifest(t *testing.T) {
	// Given
	manager, audit, runtime := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	runtime.mu.Lock()
	runtime.active = "preexisting-digest"
	runtime.activeRevision = "preexisting-revision"
	runtime.activePath = "/runtime/preexisting-manifest.json"
	runtime.failHealth = true
	runtime.mu.Unlock()
	bundle := validBundle("rev-1", "r1")
	pin := SourcePin{URL: "https://rules.example.test/rev-1", Revision: "rev-1", SHA256: sha256Hex(bundle)}
	if _, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: pin, FinalURL: pin.URL, Content: bundle, verified: true}); err != nil {
		t.Fatalf("stage candidate: %v", err)
	}

	// When
	_, activateErr := manager.Activate(context.Background(), actor, "rev-1")

	// Then
	if !errors.Is(activateErr, ErrHealth) {
		t.Fatalf("activation error = %v, want ErrHealth", activateErr)
	}
	state := runtime.snapshot()
	if state.Digest != "preexisting-digest" || state.Revision != "preexisting-revision" || state.ManifestPath != "/runtime/preexisting-manifest.json" {
		t.Fatalf("runtime was not restored exactly: %#v", state)
	}
	if !audit.contains("rule.rollback", AuditResultSucceeded) {
		t.Fatalf("missing successful runtime rollback audit: %#v", audit.events)
	}
}

func TestManager_stage_local_requires_caller_digest_and_records_parse_persist_without_premature_sync_success(t *testing.T) {
	// Given
	manager, audit, _ := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	bundle := validBundle("local-1", "r1")
	source := LocalSource{SourceID: "custom-rules", Revision: "local-1", SHA256: sha256Hex(bundle), Content: bundle}

	// When
	preview, err := manager.StageLocal(context.Background(), actor, source)

	// Then
	if err != nil || preview.Digest != source.SHA256 {
		t.Fatalf("stage local source: preview=%#v err=%v", preview, err)
	}
	if audit.contains("rule.source.sync", AuditResultSucceeded) {
		t.Fatalf("sync success was recorded before activation: %#v", audit.events)
	}
	for _, action := range []string{"rule.source.parse", "rule.source.persist"} {
		if !audit.contains(action, AuditResultSucceeded) {
			t.Fatalf("missing %s audit: %#v", action, audit.events)
		}
	}
	bad := source
	bad.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := manager.StageLocal(context.Background(), actor, bad); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("caller digest mismatch error = %v", err)
	}
}

func TestManager_stage_preview_rejects_caller_forged_remote_source(t *testing.T) {
	// Given
	manager, _, _ := newTestManager(t)
	bundle := validBundle("rev-1", "r1")
	pin := SourcePin{URL: "https://rules.example.test/rev-1", Revision: "rev-1", SHA256: sha256Hex(bundle)}

	// When
	_, err := manager.StagePreview(context.Background(), Actor{ID: "admin-1", Role: RoleAdmin}, FetchedSource{Pin: pin, FinalURL: pin.URL, Content: bundle})

	// Then
	if !errors.Is(err, ErrURLPolicy) {
		t.Fatalf("forged fetched source error = %v, want ErrURLPolicy", err)
	}
}

func TestRuleCategory_yara_manifest_uses_hids_source_category(t *testing.T) {
	// Given
	contents, err := os.ReadFile(filepath.Join("..", "..", "rules", "subscriptions", "yara-signature-base", "manifest.json"))
	if err != nil {
		t.Fatalf("read YARA manifest: %v", err)
	}
	var manifest struct {
		Category     string `json:"category"`
		CompiledPath string `json:"compiled_path"`
	}
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode YARA manifest: %v", err)
	}

	// When
	category := manifest.Category

	// Then
	if category != "hids" {
		t.Fatalf("YARA category = %q, want hids", category)
	}
	if manifest.CompiledPath != "rules/compiled/hids/yara-signature-base.json" {
		t.Fatalf("YARA compiled path = %q, want hids path", manifest.CompiledPath)
	}
}

func TestManager_activation_commit_failure_restores_exact_runtime_and_manifest(t *testing.T) {
	// Given
	manager, audit, runtime := newTestManager(t)
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	first := validBundle("rev-1", "r1")
	firstPin := SourcePin{URL: "https://rules.example.test/rev-1", Revision: "rev-1", SHA256: sha256Hex(first)}
	if _, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: firstPin, FinalURL: firstPin.URL, Content: first, verified: true}); err != nil {
		t.Fatalf("stage first: %v", err)
	}
	if _, err := manager.Activate(context.Background(), actor, "rev-1"); err != nil {
		t.Fatalf("activate first: %v", err)
	}
	previousRuntime := runtime.snapshot()
	second := validBundle("rev-2", "r2")
	secondPin := SourcePin{URL: "https://rules.example.test/rev-2", Revision: "rev-2", SHA256: sha256Hex(second)}
	if _, err := manager.StagePreview(context.Background(), actor, FetchedSource{Pin: secondPin, FinalURL: secondPin.URL, Content: second, verified: true}); err != nil {
		t.Fatalf("stage second: %v", err)
	}
	injected := errors.New("injected post-activation database failure")

	// When
	_, activateErr := manager.ActivateWithCommit(context.Background(), actor, "rev-2", func() error { return injected })
	active, activeErr := manager.Active(context.Background())

	// Then
	if !errors.Is(activateErr, injected) || activeErr != nil {
		t.Fatalf("activation errors: activate=%v active=%v", activateErr, activeErr)
	}
	if active.Revision != "rev-1" || runtime.snapshot() != previousRuntime {
		t.Fatalf("compensation mismatch: manifest=%#v runtime=%#v want=%#v", active, runtime.snapshot(), previousRuntime)
	}
	if !audit.contains("rule.activate", AuditResultFailed) || !audit.contains("rule.rollback", AuditResultSucceeded) {
		t.Fatalf("missing compensation audit: %#v", audit.events)
	}
}

func TestManager_stage_local_durably_audits_redacted_early_failure_stage(t *testing.T) {
	// Given
	manager, audit, _ := newTestManager(t)
	manager.fetcher = &Fetcher{policy: FetchPolicy{MaxBytes: 8}}
	actor := Actor{ID: "admin-1", Role: RoleAdmin}
	valid := validBundle("conflict-1", "r1")
	manager.fetcher.policy.MaxBytes = int64(len(valid) + 1)
	if _, err := manager.StageLocal(context.Background(), actor, LocalSource{SourceID: "fixture", Revision: "conflict-1", SHA256: sha256Hex(valid), Content: valid}); err != nil {
		t.Fatalf("stage conflict baseline: %v", err)
	}
	conflict := validBundle("conflict-1", "r2")
	tests := []struct {
		name   string
		stage  string
		source LocalSource
	}{
		{name: "digest", stage: "digest", source: LocalSource{SourceID: "fixture", Revision: "digest-1", SHA256: strings.Repeat("a", 64), Content: validBundle("digest-1", "r1")}},
		{name: "size", stage: "size", source: LocalSource{SourceID: "fixture", Revision: "size-1", SHA256: sha256Hex([]byte(strings.Repeat("x", len(valid)+2))), Content: []byte(strings.Repeat("x", len(valid)+2))}},
		{name: "parse", stage: "parse", source: LocalSource{SourceID: "fixture", Revision: "parse-1", SHA256: sha256Hex([]byte("secret malformed payload")), Content: []byte("secret malformed payload")}},
		{name: "conflict", stage: "conflict", source: LocalSource{SourceID: "fixture", Revision: "conflict-1", SHA256: sha256Hex(conflict), Content: conflict}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			_, err := manager.StageLocal(context.Background(), actor, test.source)

			// Then
			if err == nil || !audit.containsStage("rule.source.inline.outcome", AuditResultFailed, test.stage) {
				t.Fatalf("stage %s error=%v audit=%#v", test.stage, err, audit.events)
			}
			for _, event := range audit.events {
				if encoded, marshalErr := json.Marshal(event.Fields); marshalErr != nil || strings.Contains(string(encoded), "secret malformed payload") {
					t.Fatalf("audit leaked inline content: fields=%s err=%v", encoded, marshalErr)
				}
			}
		})
	}
}
