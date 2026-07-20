package rulelifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

const (
	lifecycleDirMode  os.FileMode = 0o755
	lifecycleFileMode os.FileMode = 0o644
)

type BootstrapConfig struct {
	RootDir      string
	BaselinePath string
	Signer       trustroot.Signer
	Verifier     trustroot.Layout
	Now          func() time.Time
}

func BootstrapActiveManifest(config BootstrapConfig) (ActiveManifest, error) {
	if config.RootDir == "" || config.BaselinePath == "" || !config.Signer.Valid() || config.Verifier.TrustDir == "" || config.Now == nil {
		return ActiveManifest{}, errors.New("rulelifecycle: invalid bootstrap configuration")
	}
	manager := &Manager{rootDir: config.RootDir, signer: config.Signer, verifier: config.Verifier, now: config.Now}
	active, _, err := manager.loadActive()
	if err == nil {
		if err := normalizeActivePermissions(config.RootDir, active.BundlePath); err != nil {
			return ActiveManifest{}, err
		}
		return active, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ActiveManifest{}, err
	}
	partial, err := lifecycleContainsFiles(config.RootDir)
	if err != nil {
		return ActiveManifest{}, err
	}
	if partial {
		return ActiveManifest{}, fmt.Errorf("partial rule lifecycle state: %w", ErrRevision)
	}
	return publishBaseline(config)
}

func publishBaseline(config BootstrapConfig) (ActiveManifest, error) {
	info, err := os.Lstat(config.BaselinePath)
	if err != nil {
		return ActiveManifest{}, fmt.Errorf("inspect packaged baseline bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ActiveManifest{}, fmt.Errorf("packaged baseline bundle is not regular: %w", ErrCompile)
	}
	contents, err := os.ReadFile(config.BaselinePath)
	if err != nil {
		return ActiveManifest{}, fmt.Errorf("read packaged baseline bundle: %w", err)
	}
	var bundle strictBundle
	if err := json.Unmarshal(contents, &bundle); err != nil || bundle.Version == "" {
		return ActiveManifest{}, fmt.Errorf("read packaged baseline revision: %w", ErrCompile)
	}
	preview, err := compileStrict(contents, bundle.Version)
	if err != nil {
		return ActiveManifest{}, err
	}
	digestBytes := sha256.Sum256(contents)
	digest := hex.EncodeToString(digestBytes[:])
	candidateDir := filepath.Join(config.RootDir, "candidates", bundle.Version)
	bundlePath := filepath.Join(candidateDir, digest+".json")
	for _, directory := range []string{config.RootDir, filepath.Join(config.RootDir, "candidates"), filepath.Join(config.RootDir, "history"), candidateDir} {
		if err := os.MkdirAll(directory, lifecycleDirMode); err != nil {
			return ActiveManifest{}, fmt.Errorf("create baseline lifecycle directory: %w", err)
		}
		if err := os.Chmod(directory, lifecycleDirMode); err != nil {
			return ActiveManifest{}, fmt.Errorf("set baseline lifecycle directory mode: %w", err)
		}
	}
	if err := immutableWrite(bundlePath, contents, lifecycleFileMode); err != nil {
		return ActiveManifest{}, err
	}
	metadata, err := json.Marshal(stagedCandidate{
		Pin:      SourcePin{URL: "package://rules/security-engine/active-bundle.json", Revision: bundle.Version, SHA256: digest},
		FinalURL: "package://rules/security-engine/active-bundle.json", BundlePath: bundlePath, RuleCount: preview.RuleCount,
	})
	if err != nil {
		return ActiveManifest{}, fmt.Errorf("marshal baseline candidate: %w", err)
	}
	if err := atomicWrite(filepath.Join(candidateDir, "candidate.json"), metadata, lifecycleFileMode); err != nil {
		return ActiveManifest{}, err
	}
	manifest := ActiveManifest{
		SchemaVersion: "lyflow.rule-manifest/v1", Revision: bundle.Version, Digest: digest, BundlePath: bundlePath,
		SourceURL: "package://rules/security-engine/active-bundle.json", SourceRevision: bundle.Version,
		ActivatedAt: config.Now().UTC(), SignerFingerprint: config.Signer.Fingerprint(),
	}
	manifest, err = signManifest(manifest, config.Signer)
	if err != nil {
		return ActiveManifest{}, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return ActiveManifest{}, fmt.Errorf("marshal signed baseline manifest: %w", err)
	}
	if err := atomicWrite(filepath.Join(config.RootDir, activeManifestName), manifestJSON, lifecycleFileMode); err != nil {
		return ActiveManifest{}, err
	}
	return manifest, nil
}

func lifecycleContainsFiles(root string) (bool, error) {
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == root && errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if path != root && !entry.IsDir() {
			return errLifecycleContent
		}
		return nil
	})
	if errors.Is(err, errLifecycleContent) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect lifecycle bootstrap state: %w", err)
	}
	return false, nil
}

func normalizeActivePermissions(root, bundlePath string) error {
	for _, directory := range []string{root, filepath.Join(root, "candidates"), filepath.Join(root, "history"), filepath.Dir(bundlePath)} {
		if err := os.Chmod(directory, lifecycleDirMode); err != nil {
			return fmt.Errorf("set active lifecycle directory mode: %w", err)
		}
	}
	for _, path := range []string{bundlePath, filepath.Join(root, activeManifestName)} {
		if err := os.Chmod(path, lifecycleFileMode); err != nil {
			return fmt.Errorf("set active lifecycle file mode: %w", err)
		}
	}
	return nil
}

var errLifecycleContent = errors.New("rulelifecycle: lifecycle content exists")
