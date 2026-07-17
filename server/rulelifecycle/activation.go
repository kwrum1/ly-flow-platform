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
)

func (m *Manager) Activate(ctx context.Context, actor Actor, revision string) (ActiveManifest, error) {
	return m.activate(ctx, actor, revision, "rule.activate", nil)
}

func (m *Manager) ActivateWithCommit(ctx context.Context, actor Actor, revision string, commit func() error) (ActiveManifest, error) {
	if commit == nil {
		return ActiveManifest{}, errors.New("rulelifecycle: activation commit is required")
	}
	return m.activate(ctx, actor, revision, "rule.activate", commit)
}

func (m *Manager) Rollback(ctx context.Context, actor Actor, revision string) (ActiveManifest, error) {
	return m.activate(ctx, actor, revision, "rule.rollback", nil)
}

func (m *Manager) Reload(ctx context.Context, actor Actor) error {
	if err := m.authorize(ctx, actor, "rule.reload", "active"); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	manifest, _, err := m.loadActive()
	if err != nil {
		return err
	}
	if err := m.runtime.Reload(ctx, filepath.Join(m.rootDir, activeManifestName), manifest.Digest); err != nil {
		return m.reloadFailure(ctx, actor, manifest, err)
	}
	if err := m.runtime.Health(ctx, manifest.Revision, manifest.Digest); err != nil {
		return m.reloadFailure(ctx, actor, manifest, fmt.Errorf("reload health: %w", ErrHealth))
	}
	return m.record(ctx, actor, "rule.reload", manifest.Revision, AuditResultSucceeded, map[string]interface{}{"digest": manifest.Digest})
}

func (m *Manager) reloadFailure(ctx context.Context, actor Actor, manifest ActiveManifest, cause error) error {
	if err := m.record(ctx, actor, "rule.reload", manifest.Revision, AuditResultFailed, map[string]interface{}{"error": cause.Error()}); err != nil {
		return err
	}
	return cause
}

func (m *Manager) activate(ctx context.Context, actor Actor, revision, action string, commit func() error) (ActiveManifest, error) {
	if err := m.authorize(ctx, actor, action, revision); err != nil {
		return ActiveManifest{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate, err := m.loadCandidate(revision)
	if err != nil {
		return ActiveManifest{}, err
	}
	previous, previousJSON, previousErr := m.loadActive()
	if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
		return ActiveManifest{}, previousErr
	}
	if previousErr == nil && previous.Revision == revision && previous.Digest == candidate.Pin.SHA256 {
		if err := m.runtime.Health(ctx, revision, candidate.Pin.SHA256); err != nil {
			if auditErr := m.record(ctx, actor, action, revision, AuditResultFailed, map[string]interface{}{"error": err.Error(), "idempotent": true}); auditErr != nil {
				return ActiveManifest{}, auditErr
			}
			return ActiveManifest{}, fmt.Errorf("active candidate %s: %w", revision, ErrHealth)
		}
		if commit != nil {
			if err := commit(); err != nil {
				if auditErr := m.record(ctx, actor, action, revision, AuditResultFailed, map[string]interface{}{"error": "post-activation commit failed", "idempotent": true}); auditErr != nil {
					return ActiveManifest{}, errors.Join(err, auditErr)
				}
				return ActiveManifest{}, fmt.Errorf("commit active candidate: %w", err)
			}
		}
		if err := m.record(ctx, actor, action, revision, AuditResultSucceeded, map[string]interface{}{"digest": previous.Digest, "idempotent": true}); err != nil {
			return ActiveManifest{}, err
		}
		return previous, nil
	}
	runtimeState, err := m.runtime.Snapshot(ctx)
	if err != nil {
		if auditErr := m.record(ctx, actor, "rule.runtime.snapshot", revision, AuditResultFailed, map[string]interface{}{"error": err.Error()}); auditErr != nil {
			return ActiveManifest{}, auditErr
		}
		return ActiveManifest{}, fmt.Errorf("snapshot runtime: %w", err)
	}
	if err := m.record(ctx, actor, "rule.runtime.snapshot", revision, AuditResultSucceeded, map[string]interface{}{"digest": runtimeState.Digest, "revision": runtimeState.Revision}); err != nil {
		return ActiveManifest{}, err
	}
	manifest := ActiveManifest{SchemaVersion: "lyflow.rule-manifest/v1", Revision: revision, Digest: candidate.Pin.SHA256, BundlePath: candidate.BundlePath, SourceURL: candidate.FinalURL, SourceRevision: candidate.Pin.Revision, ActivatedAt: m.now().UTC(), SignerFingerprint: m.signer.Fingerprint()}
	if previousErr == nil {
		manifest.PreviousRevision = previous.Revision
	}
	manifest, err = signManifest(manifest, m.signer)
	if err != nil {
		return ActiveManifest{}, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return ActiveManifest{}, fmt.Errorf("marshal signed manifest: %w", err)
	}
	activePath := filepath.Join(m.rootDir, activeManifestName)
	if previousErr == nil {
		historyDigest := sha256.Sum256(previousJSON)
		historyPath := filepath.Join(m.rootDir, "history", previous.Revision+"-"+hex.EncodeToString(historyDigest[:])+".json")
		if err := immutableWrite(historyPath, previousJSON, 0o600); err != nil {
			return ActiveManifest{}, err
		}
	}
	if err := atomicWrite(activePath, manifestJSON, 0o600); err != nil {
		return ActiveManifest{}, err
	}
	if err := m.runtime.Reload(ctx, activePath, candidate.Pin.SHA256); err != nil {
		cause := fmt.Errorf("reload candidate: %w", err)
		rollbackErr := errors.Join(m.restoreActive(activePath, previousJSON, previousErr), m.restoreRuntime(ctx, actor, runtimeState))
		auditErr := m.record(ctx, actor, "rule.reload", revision, AuditResultFailed, map[string]interface{}{"error": err.Error()})
		return ActiveManifest{}, errors.Join(cause, rollbackErr, auditErr)
	}
	if err := m.runtime.Health(ctx, revision, candidate.Pin.SHA256); err != nil {
		cause := fmt.Errorf("candidate %s: %w", revision, ErrHealth)
		rollbackErr := errors.Join(m.restoreActive(activePath, previousJSON, previousErr), m.restoreRuntime(ctx, actor, runtimeState))
		reloadAuditErr := m.record(ctx, actor, "rule.reload", revision, AuditResultFailed, map[string]interface{}{"error": err.Error()})
		actionAuditErr := m.record(ctx, actor, action, revision, AuditResultFailed, map[string]interface{}{"error": err.Error()})
		return ActiveManifest{}, errors.Join(cause, rollbackErr, reloadAuditErr, actionAuditErr)
	}
	if commit != nil {
		if err := commit(); err != nil {
			cause := fmt.Errorf("commit activated candidate: %w", err)
			rollbackErr := errors.Join(m.restoreActive(activePath, previousJSON, previousErr), m.restoreRuntime(ctx, actor, runtimeState))
			reloadAuditErr := m.record(ctx, actor, "rule.reload", revision, AuditResultFailed, map[string]interface{}{"error": "post-activation commit failed"})
			actionAuditErr := m.record(ctx, actor, action, revision, AuditResultFailed, map[string]interface{}{"error": "post-activation commit failed"})
			return ActiveManifest{}, errors.Join(cause, rollbackErr, reloadAuditErr, actionAuditErr)
		}
	}
	if err := m.record(ctx, actor, "rule.reload", revision, AuditResultSucceeded, map[string]interface{}{"digest": candidate.Pin.SHA256}); err != nil {
		rollbackErr := errors.Join(m.restoreActive(activePath, previousJSON, previousErr), m.restoreRuntime(ctx, actor, runtimeState))
		return ActiveManifest{}, errors.Join(err, rollbackErr)
	}
	if err := m.record(ctx, actor, action, revision, AuditResultSucceeded, map[string]interface{}{"digest": manifest.Digest, "previous_revision": manifest.PreviousRevision}); err != nil {
		rollbackErr := errors.Join(m.restoreActive(activePath, previousJSON, previousErr), m.restoreRuntime(ctx, actor, runtimeState))
		return ActiveManifest{}, errors.Join(err, rollbackErr)
	}
	return manifest, nil
}
