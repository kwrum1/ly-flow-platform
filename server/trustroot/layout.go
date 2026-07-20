package trustroot

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Layout struct {
	TrustDir string
	KeyDir   string
}

func DefaultLayout() Layout {
	return Layout{TrustDir: "/etc/lyflow/trust", KeyDir: "/var/lib/lyflow/keys"}
}

func (l Layout) EnsureOnlineRoots(random io.Reader) error {
	if err := rejectSymlinkPath(l.TrustDir); err != nil {
		return err
	}
	if err := rejectSymlinkPath(l.KeyDir); err != nil {
		return err
	}
	existing := 0
	for _, role := range []RootRole{PolicyRoot, AuditRoot, RuleRoot} {
		keyRole, err := role.OnlineKeyRole()
		if err != nil {
			return err
		}
		for _, path := range []string{l.RootPath(role), l.KeyPath(keyRole)} {
			if _, err := os.Lstat(path); err == nil {
				existing++
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect online root layout: %w", err)
			}
		}
	}
	if existing == 0 {
		if err := l.Bootstrap(random); err != nil {
			return err
		}
		return l.normalizeOnlineModes()
	}
	if existing != 6 {
		return ErrIncompleteLayout
	}
	return l.normalizeOnlineModes()
}

func rejectSymlinkPath(path string) error {
	probe := filepath.Clean(path)
	for {
		info, err := os.Lstat(probe)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("trust root path is a symlink: %w", ErrMalformedRoot)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect trust root path: %w", err)
		}
		next := filepath.Dir(probe)
		if next == probe {
			return nil
		}
		probe = next
	}
}

func (l Layout) normalizeOnlineModes() error {
	trustParent := filepath.Dir(l.TrustDir)
	if trustParent == filepath.Dir(l.KeyDir) && trustParent != "." && trustParent != string(filepath.Separator) {
		if err := normalizeDirectoryMode(trustParent, 0o755); err != nil {
			return fmt.Errorf("make online root parent traversable: %w", err)
		}
	}
	if err := normalizeDirectoryMode(l.TrustDir, 0o755); err != nil {
		return fmt.Errorf("make online roots traversable: %w", err)
	}
	if err := normalizeDirectoryMode(l.KeyDir, 0o700); err != nil {
		return fmt.Errorf("secure online key directory: %w", err)
	}
	for _, role := range []RootRole{PolicyRoot, AuditRoot, RuleRoot} {
		if err := normalizeRegularFileMode(l.RootPath(role), 0o644); err != nil {
			return fmt.Errorf("make %s root readable: %w", role, err)
		}
		keyRole, err := role.OnlineKeyRole()
		if err != nil {
			return err
		}
		if err := normalizeRegularFileMode(l.KeyPath(keyRole), 0o600); err != nil {
			return fmt.Errorf("secure %s signer: %w", role, err)
		}
	}
	return nil
}

func normalizeDirectoryMode(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrMalformedRoot
	}
	return os.Chmod(path, mode)
}

func normalizeRegularFileMode(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrMalformedRoot
	}
	return os.Chmod(path, mode)
}

func (l Layout) RootPath(role RootRole) string {
	return filepath.Join(l.TrustDir, string(role)+"-root.pem")
}

func (l Layout) previousRootPath(role RootRole) string {
	return filepath.Join(l.TrustDir, string(role)+"-root.previous.pem")
}

func (l Layout) KeyPath(role KeyRole) string {
	return filepath.Join(l.KeyDir, string(role)+"-signer.key")
}

func (l Layout) Bootstrap(random io.Reader) error {
	if err := os.MkdirAll(l.TrustDir, 0o755); err != nil {
		return fmt.Errorf("create trust directory: %w", err)
	}
	if err := os.MkdirAll(l.KeyDir, 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(l.KeyDir, 0o700); err != nil {
		return fmt.Errorf("secure key directory: %w", err)
	}
	for _, role := range []RootRole{PolicyRoot, AuditRoot, RuleRoot} {
		if err := l.generate(role, random); err != nil {
			return err
		}
	}
	return nil
}

func (l Layout) generate(role RootRole, random io.Reader) error {
	keyRole, err := role.OnlineKeyRole()
	if err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return fmt.Errorf("generate %s signer: %w", role, err)
	}
	publicPEM, err := marshalPublicRoot(publicKey)
	if err != nil {
		return fmt.Errorf("marshal %s root: %w", role, err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal %s signer: %w", role, err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := atomicWrite(l.KeyPath(keyRole), privatePEM, 0o600); err != nil {
		return fmt.Errorf("write %s signer: %w", role, err)
	}
	if err := atomicWrite(l.RootPath(role), publicPEM, 0o644); err != nil {
		return fmt.Errorf("write %s root: %w", role, err)
	}
	return nil
}

func (l Layout) LoadSigner(role KeyRole) (Signer, error) {
	info, err := os.Lstat(l.KeyPath(role))
	if err != nil {
		return Signer{}, fmt.Errorf("inspect %s signer: %w", role, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Signer{}, ErrMalformedRoot
	}
	contents, err := os.ReadFile(l.KeyPath(role))
	if err != nil {
		return Signer{}, fmt.Errorf("read %s signer: %w", role, err)
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return Signer{}, ErrMalformedRoot
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Signer{}, fmt.Errorf("parse %s signer: %w", role, ErrMalformedRoot)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return Signer{}, ErrMalformedRoot
	}
	return Signer{privateKey: privateKey}, nil
}
