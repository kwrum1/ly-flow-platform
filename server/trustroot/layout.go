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
	existing := 0
	for _, role := range []RootRole{PolicyRoot, AuditRoot, RuleRoot} {
		keyRole, err := role.OnlineKeyRole()
		if err != nil {
			return err
		}
		for _, path := range []string{l.RootPath(role), l.KeyPath(keyRole)} {
			if _, err := os.Stat(path); err == nil {
				existing++
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect online root layout: %w", err)
			}
		}
	}
	if existing == 0 {
		return l.Bootstrap(random)
	}
	if existing != 6 {
		return ErrIncompleteLayout
	}
	return nil
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
