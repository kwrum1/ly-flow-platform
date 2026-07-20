package rulelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (m *Manager) loadCandidate(revision string) (stagedCandidate, error) {
	if err := validatePin(SourcePin{Revision: revision, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}); err != nil {
		return stagedCandidate{}, err
	}
	contents, err := os.ReadFile(filepath.Join(m.rootDir, "candidates", revision, "candidate.json"))
	if err != nil {
		return stagedCandidate{}, fmt.Errorf("read staged candidate: %w", err)
	}
	var candidate stagedCandidate
	if err := json.Unmarshal(contents, &candidate); err != nil {
		return stagedCandidate{}, fmt.Errorf("decode staged candidate: %w", err)
	}
	if candidate.Pin.Revision != revision {
		return stagedCandidate{}, ErrRevision
	}
	if err := m.verifyBundle(candidate.BundlePath, candidate.Pin.SHA256, revision); err != nil {
		return stagedCandidate{}, err
	}
	return candidate, nil
}

func (m *Manager) restoreRuntime(ctx context.Context, actor Actor, previous RuntimeState) error {
	err := m.runtime.Restore(ctx, previous)
	result := AuditResultSucceeded
	fields := map[string]interface{}{"digest": previous.Digest, "manifest_path": previous.ManifestPath}
	if err != nil {
		result = AuditResultFailed
		fields["error"] = err.Error()
	}
	resource := previous.Revision
	if resource == "" {
		resource = "preexisting-runtime"
	}
	if auditErr := m.record(ctx, actor, "rule.rollback", resource, result, fields); auditErr != nil {
		return auditErr
	}
	return err
}

func (m *Manager) restoreActive(activePath string, previousJSON []byte, previousErr error) error {
	if previousErr == nil {
		return atomicWrite(activePath, previousJSON, lifecycleFileMode)
	}
	if errors.Is(previousErr, os.ErrNotExist) {
		if err := os.Remove(activePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove failed candidate manifest: %w", err)
		}
	}
	return nil
}
