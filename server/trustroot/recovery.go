package trustroot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func (l Layout) Backup(destination string) error {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return fmt.Errorf("create trust backup: %w", err)
	}
	if err := copyTree(l.TrustDir, filepath.Join(destination, "trust")); err != nil {
		return fmt.Errorf("backup public roots: %w", err)
	}
	if err := copyTree(l.KeyDir, filepath.Join(destination, "keys")); err != nil {
		return fmt.Errorf("backup online signers: %w", err)
	}
	return nil
}

func (l Layout) Recover(source string) error {
	snapshot := Layout{TrustDir: filepath.Join(source, "trust"), KeyDir: filepath.Join(source, "keys")}
	state, err := snapshot.loadRevocations()
	if err != nil {
		return fmt.Errorf("read recovery revocations: %w", err)
	}
	for _, role := range []RootRole{PolicyRoot, AuditRoot, RuleRoot, ReleaseRoot} {
		contents, err := os.ReadFile(snapshot.RootPath(role))
		if role == ReleaseRoot && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read recovery %s root: %w", role, err)
		}
		publicKey, err := ParsePublicRoot(contents)
		if err != nil {
			return err
		}
		if isRevoked(state, role, fingerprint(publicKey)) {
			return ErrRootRevoked
		}
	}
	if err := copyTree(snapshot.TrustDir, l.TrustDir); err != nil {
		return fmt.Errorf("recover public roots: %w", err)
	}
	if err := copyTree(snapshot.KeyDir, l.KeyDir); err != nil {
		return fmt.Errorf("recover online signers: %w", err)
	}
	return nil
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(target, info.Mode().Perm())
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return atomicWrite(target, contents, info.Mode().Perm())
	})
}

func atomicWrite(path string, contents []byte, mode os.FileMode) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, temporary.Close())
		}
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return nil
}
