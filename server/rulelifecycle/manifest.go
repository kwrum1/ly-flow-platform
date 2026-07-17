package rulelifecycle

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

func signManifest(manifest ActiveManifest, signer trustroot.Signer) (ActiveManifest, error) {
	manifest.Signature = ""
	payload, err := json.Marshal(manifest)
	if err != nil {
		return ActiveManifest{}, fmt.Errorf("marshal active manifest: %w", err)
	}
	manifest.Signature = hex.EncodeToString(signer.Sign(payload))
	return manifest, nil
}

func verifyManifest(manifest ActiveManifest, verifier trustroot.Layout) error {
	if manifest.SourceRevision != manifest.Revision {
		return ErrRevision
	}
	signature, err := hex.DecodeString(manifest.Signature)
	if err != nil {
		return ErrManifestSignature
	}
	unsigned := manifest
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal manifest verification payload: %w", err)
	}
	if err := verifier.VerifyAttributed(trustroot.RuleRoot, payload, signature, manifest.SignerFingerprint); err != nil {
		return fmt.Errorf("verify rule manifest: %w", ErrManifestSignature)
	}
	return nil
}

func (m *Manager) loadActive() (ActiveManifest, []byte, error) {
	contents, err := os.ReadFile(filepath.Join(m.rootDir, activeManifestName))
	if errors.Is(err, os.ErrNotExist) {
		return ActiveManifest{}, nil, os.ErrNotExist
	}
	if err != nil {
		return ActiveManifest{}, nil, fmt.Errorf("read active manifest: %w", err)
	}
	var manifest ActiveManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		return ActiveManifest{}, nil, fmt.Errorf("decode active manifest: %w", ErrManifestSignature)
	}
	if err := verifyManifest(manifest, m.verifier); err != nil {
		return ActiveManifest{}, nil, err
	}
	if err := m.verifyBundle(manifest.BundlePath, manifest.Digest, manifest.Revision); err != nil {
		return ActiveManifest{}, nil, err
	}
	return manifest, contents, nil
}

func (m *Manager) verifyBundle(path, digest, revision string) error {
	absRoot, err := filepath.Abs(m.rootDir)
	if err != nil {
		return fmt.Errorf("resolve lifecycle root: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve bundle path: %w", err)
	}
	relative, err := filepath.Rel(absRoot, absPath)
	if err != nil || relative == ".." || len(relative) >= 3 && relative[:3] == ".."+string(filepath.Separator) {
		return fmt.Errorf("bundle path escapes lifecycle root: %w", ErrCompile)
	}
	contents, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("read staged bundle: %w", err)
	}
	actual := sha256.Sum256(contents)
	expected, err := hex.DecodeString(digest)
	if err != nil || subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return ErrDigestMismatch
	}
	if _, err := compileStrict(contents, revision); err != nil {
		return err
	}
	return nil
}
