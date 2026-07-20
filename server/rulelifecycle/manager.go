package rulelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type stagedCandidate struct {
	Pin        SourcePin `json:"pin"`
	FinalURL   string    `json:"final_url"`
	BundlePath string    `json:"bundle_path"`
	RuleCount  int       `json:"rule_count"`
}

type Manager struct {
	mu       sync.Mutex
	rootDir  string
	signer   trustroot.Signer
	verifier trustroot.Layout
	audit    Audit
	runtime  Runtime
	fetcher  *Fetcher
	now      func() time.Time
}

func NewManager(config ManagerConfig) (*Manager, error) {
	if config.RootDir == "" || config.Audit == nil || config.Runtime == nil || config.Now == nil || !config.Signer.Valid() || config.Verifier.TrustDir == "" {
		return nil, errors.New("rulelifecycle: invalid manager configuration")
	}
	for _, directory := range []string{config.RootDir, filepath.Join(config.RootDir, "candidates"), filepath.Join(config.RootDir, "history")} {
		if err := os.MkdirAll(directory, lifecycleDirMode); err != nil {
			return nil, fmt.Errorf("create rule lifecycle storage: %w", err)
		}
	}
	return &Manager{rootDir: config.RootDir, signer: config.Signer, verifier: config.Verifier, audit: config.Audit, runtime: config.Runtime, fetcher: config.Fetcher, now: config.Now}, nil
}

func (m *Manager) Sync(ctx context.Context, actor Actor, pin SourcePin) (Preview, error) {
	fetched, err := m.FetchSource(ctx, actor, pin)
	if err != nil {
		return Preview{}, err
	}
	preview, err := m.stage(ctx, actor, fetched)
	if err != nil {
		return Preview{}, err
	}
	if _, err := m.Activate(ctx, actor, pin.Revision); err != nil {
		if auditErr := m.record(ctx, actor, "rule.source.sync", pin.Revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		return Preview{}, err
	}
	if err := m.record(ctx, actor, "rule.source.sync", pin.Revision, AuditResultSucceeded, map[string]interface{}{"digest": preview.Digest}); err != nil {
		return Preview{}, err
	}
	return preview, nil
}

func (m *Manager) FetchSource(ctx context.Context, actor Actor, pin SourcePin) (FetchedSource, error) {
	if err := m.authorize(ctx, actor, "rule.source.sync", pin.Revision); err != nil {
		return FetchedSource{}, err
	}
	if m.fetcher == nil {
		return FetchedSource{}, errors.New("rulelifecycle: fetcher is not configured")
	}
	if err := m.record(ctx, actor, "rule.source.fetch.attempt", pin.Revision, AuditResultSucceeded, map[string]interface{}{"digest": pin.SHA256}); err != nil {
		return FetchedSource{}, err
	}
	fetched, err := m.fetcher.Fetch(ctx, pin)
	if err != nil {
		if auditErr := m.record(ctx, actor, "rule.source.fetch.outcome", pin.Revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return FetchedSource{}, auditErr
		}
		return FetchedSource{}, err
	}
	if err := m.record(ctx, actor, "rule.source.fetch.outcome", pin.Revision, AuditResultSucceeded, map[string]interface{}{"digest": pin.SHA256, "final_url": fetched.FinalURL}); err != nil {
		return FetchedSource{}, err
	}
	return fetched, nil
}

func (m *Manager) ValidateSourceURL(ctx context.Context, rawURL string) error {
	if m.fetcher == nil {
		return errors.New("rulelifecycle: fetcher is not configured")
	}
	_, _, err := m.fetcher.validateHop(ctx, rawURL)
	return err
}

func (m *Manager) StagePreview(ctx context.Context, actor Actor, source FetchedSource) (Preview, error) {
	if err := m.authorize(ctx, actor, "rule.source.sync", source.Pin.Revision); err != nil {
		return Preview{}, err
	}
	if !source.verified {
		if auditErr := m.record(ctx, actor, "rule.source.fetch.outcome", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": ErrURLPolicy.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		return Preview{}, ErrURLPolicy
	}
	return m.stage(ctx, actor, source)
}

func (m *Manager) StageLocal(ctx context.Context, actor Actor, source LocalSource) (Preview, error) {
	if err := m.authorize(ctx, actor, "rule.source.inline", source.Revision); err != nil {
		return Preview{}, err
	}
	resource := source.SourceID + ":" + source.Revision
	if err := m.record(ctx, actor, "rule.source.inline.attempt", resource, AuditResultSucceeded, map[string]interface{}{"source_type": "local"}); err != nil {
		return Preview{}, err
	}
	if source.SourceID == "" || len(source.Content) == 0 {
		return Preview{}, m.inlineFailure(ctx, actor, inlineFailureAudit{resource: resource, stage: "parse", cause: ErrRevision})
	}
	maxBytes := int64(64 << 20)
	if m.fetcher != nil {
		maxBytes = m.fetcher.policy.MaxBytes
	}
	if int64(len(source.Content)) > maxBytes {
		return Preview{}, m.inlineFailure(ctx, actor, inlineFailureAudit{resource: resource, stage: "size", cause: ErrSizeLimit})
	}
	preview, err := m.stage(ctx, actor, FetchedSource{
		Pin:      SourcePin{URL: "local://" + source.SourceID, Revision: source.Revision, SHA256: source.SHA256},
		FinalURL: "local://" + source.SourceID,
		Content:  source.Content,
	})
	if err != nil {
		stage := "parse"
		switch {
		case errors.Is(err, ErrDigestMismatch):
			stage = "digest"
		case errors.Is(err, ErrSizeLimit):
			stage = "size"
		case errors.Is(err, ErrRevision):
			stage = "conflict"
		}
		return Preview{}, m.inlineFailure(ctx, actor, inlineFailureAudit{resource: resource, stage: stage, cause: err})
	}
	if err := m.record(ctx, actor, "rule.source.inline.stage", source.Revision, AuditResultSucceeded, map[string]interface{}{"source_id": source.SourceID, "digest": source.SHA256}); err != nil {
		return Preview{}, err
	}
	if err := m.record(ctx, actor, "rule.source.inline.outcome", resource, AuditResultSucceeded, map[string]interface{}{"stage": "staged", "digest": source.SHA256}); err != nil {
		return Preview{}, err
	}
	return preview, nil
}

func (m *Manager) RecordOutcome(ctx context.Context, actor Actor, action, resource, result string, fields map[string]interface{}) error {
	if err := m.authorize(ctx, actor, action, resource); err != nil {
		return err
	}
	return m.record(ctx, actor, action, resource, result, fields)
}

func (m *Manager) stage(ctx context.Context, actor Actor, source FetchedSource) (Preview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validatePin(source.Pin); err != nil {
		if auditErr := m.record(ctx, actor, "rule.source.parse", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		return Preview{}, err
	}
	digest := sha256.Sum256(source.Content)
	actual := hex.EncodeToString(digest[:])
	if actual != source.Pin.SHA256 {
		if auditErr := m.record(ctx, actor, "rule.source.parse", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": ErrDigestMismatch.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		return Preview{}, ErrDigestMismatch
	}
	preview, err := compileStrict(source.Content, source.Pin.Revision)
	if err != nil {
		if auditErr := m.record(ctx, actor, "rule.source.parse", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		if auditErr := m.record(ctx, actor, "rule.compile.preview", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		return Preview{}, err
	}
	if err := m.record(ctx, actor, "rule.source.parse", source.Pin.Revision, AuditResultSucceeded, map[string]interface{}{"digest": actual, "rule_count": preview.RuleCount}); err != nil {
		return Preview{}, err
	}
	preview.Digest = actual
	directory := filepath.Join(m.rootDir, "candidates", source.Pin.Revision)
	bundlePath := filepath.Join(directory, actual+".json")
	metadataPath := filepath.Join(directory, "candidate.json")
	existingMetadata, readErr := os.ReadFile(metadataPath)
	if readErr == nil {
		var existing stagedCandidate
		if err := json.Unmarshal(existingMetadata, &existing); err != nil {
			return Preview{}, fmt.Errorf("decode existing candidate: %w", err)
		}
		if existing.Pin.SHA256 != actual {
			if auditErr := m.record(ctx, actor, "rule.source.persist", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": ErrRevision.Error()}); auditErr != nil {
				return Preview{}, auditErr
			}
			return Preview{}, ErrRevision
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return Preview{}, fmt.Errorf("read existing candidate: %w", readErr)
	}
	metadata, err := json.Marshal(stagedCandidate{Pin: source.Pin, FinalURL: source.FinalURL, BundlePath: bundlePath, RuleCount: preview.RuleCount})
	if err != nil {
		return Preview{}, fmt.Errorf("marshal staged candidate: %w", err)
	}
	if err := immutableWrite(bundlePath, source.Content, lifecycleFileMode); err != nil {
		if auditErr := m.record(ctx, actor, "rule.source.persist", source.Pin.Revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return Preview{}, auditErr
		}
		return Preview{}, err
	}
	if err := atomicWrite(metadataPath, metadata, lifecycleFileMode); err != nil {
		_ = os.Remove(bundlePath)
		return Preview{}, err
	}
	if err := m.record(ctx, actor, "rule.source.persist", source.Pin.Revision, AuditResultSucceeded, map[string]interface{}{"digest": actual, "bundle_path": bundlePath}); err != nil {
		_ = os.Remove(metadataPath)
		_ = os.Remove(bundlePath)
		return Preview{}, err
	}
	if err := m.record(ctx, actor, "rule.compile.preview", source.Pin.Revision, AuditResultSucceeded, map[string]interface{}{"digest": actual, "rule_count": preview.RuleCount}); err != nil {
		_ = os.Remove(metadataPath)
		_ = os.Remove(bundlePath)
		return Preview{}, err
	}
	return preview, nil
}

func (m *Manager) Active(_ context.Context) (ActiveManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	manifest, _, err := m.loadActive()
	return manifest, err
}

func (m *Manager) authorize(ctx context.Context, actor Actor, action, resource string) error {
	if actor.ID != "" && actor.Role == RoleAdmin {
		return nil
	}
	if err := m.record(ctx, actor, action, resource, AuditResultDenied, nil); err != nil {
		return err
	}
	return ErrForbidden
}

func (m *Manager) record(ctx context.Context, actor Actor, action, resource, result string, fields map[string]interface{}) error {
	if err := m.audit.Record(ctx, AuditEvent{Actor: actor.ID, Action: action, Resource: resource, Result: result, Fields: fields}); err != nil {
		return fmt.Errorf("record %s audit: %w: %w", action, err, ErrAudit)
	}
	return nil
}
