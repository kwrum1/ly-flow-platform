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
	"golang.org/x/sys/unix"
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

func BootstrapActiveManifest(config BootstrapConfig) (manifest ActiveManifest, err error) {
	if config.RootDir == "" || config.BaselinePath == "" || !config.Signer.Valid() || config.Verifier.TrustDir == "" || config.Now == nil {
		return ActiveManifest{}, errors.New("rulelifecycle: invalid bootstrap configuration")
	}
	if err := rejectSymlinkPath(config.RootDir); err != nil {
		return ActiveManifest{}, err
	}
	lock, err := acquireBootstrapLock(config.RootDir)
	if err != nil {
		return ActiveManifest{}, err
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("release rule lifecycle bootstrap lock: %w", closeErr)
		}
	}()
	manager := &Manager{rootDir: config.RootDir, signer: config.Signer, verifier: config.Verifier, now: config.Now}
	active, _, err := manager.loadActive()
	if err == nil {
		if err := normalizeActivePermissions(config.RootDir); err != nil {
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

func normalizeActivePermissions(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("lifecycle path is a symlink: %w", ErrCompile)
		}
		mode := lifecycleFileMode
		if entry.IsDir() {
			mode = lifecycleDirMode
		} else {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("lifecycle path is not regular: %w", ErrCompile)
			}
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("set active lifecycle mode: %w", err)
		}
		return nil
	})
}

var errLifecycleContent = errors.New("rulelifecycle: lifecycle content exists")

type bootstrapLock struct {
	file *os.File
}

func acquireBootstrapLock(root string) (*bootstrapLock, error) {
	parent := filepath.Dir(root)
	if err := os.MkdirAll(parent, lifecycleDirMode); err != nil {
		return nil, fmt.Errorf("create rule lifecycle bootstrap parent: %w", err)
	}
	path := filepath.Join(parent, "."+filepath.Base(root)+".bootstrap.lock")
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("rule lifecycle bootstrap lock is a symlink: %w", ErrRevision)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect rule lifecycle bootstrap lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, lifecycleFileMode)
	if err != nil {
		return nil, fmt.Errorf("open rule lifecycle bootstrap lock: %w", err)
	}
	if err := file.Chmod(lifecycleFileMode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("set rule lifecycle bootstrap lock mode: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock rule lifecycle bootstrap: %w", err)
	}
	return &bootstrapLock{file: file}, nil
}

func (lock *bootstrapLock) Close() error {
	return errors.Join(unix.Flock(int(lock.file.Fd()), unix.LOCK_UN), lock.file.Close())
}

func rejectSymlinkPath(path string) error {
	probe := filepath.Clean(path)
	for {
		info, err := os.Lstat(probe)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("rule lifecycle path is a symlink: %w", ErrRevision)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect rule lifecycle path: %w", err)
		}
		next := filepath.Dir(probe)
		if next == probe {
			return nil
		}
		probe = next
	}
}
