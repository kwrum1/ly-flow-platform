package trustroot

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func ParsePublicRoot(contents []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, ErrMalformedRoot
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public root: %w", ErrMalformedRoot)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrMalformedRoot
	}
	return publicKey, nil
}

func marshalPublicRoot(publicKey ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public root: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func (l Layout) InstallReleaseRoot(externalPath, bundleDir string) error {
	external, err := filepath.EvalSymlinks(externalPath)
	if err != nil {
		return fmt.Errorf("resolve release root: %w", err)
	}
	external, err = filepath.Abs(external)
	if err != nil {
		return fmt.Errorf("resolve absolute release root: %w", err)
	}
	bundle, err := filepath.EvalSymlinks(bundleDir)
	if err != nil {
		return fmt.Errorf("resolve bundle directory: %w", err)
	}
	bundle, err = filepath.Abs(bundle)
	if err != nil {
		return fmt.Errorf("resolve absolute bundle directory: %w", err)
	}
	relative, err := filepath.Rel(bundle, external)
	if err != nil {
		return fmt.Errorf("compare release root and bundle: %w", err)
	}
	if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return ErrBundleSelfTrust
	}
	contents, err := os.ReadFile(external)
	if err != nil {
		return fmt.Errorf("read external release root: %w", err)
	}
	if _, err := ParsePublicRoot(contents); err != nil {
		return err
	}
	if err := os.MkdirAll(l.TrustDir, 0o755); err != nil {
		return fmt.Errorf("create trust directory: %w", err)
	}
	if err := atomicWrite(l.RootPath(ReleaseRoot), contents, 0o644); err != nil {
		return fmt.Errorf("install release root: %w", err)
	}
	return nil
}

func (l Layout) Rotate(role RootRole, random io.Reader) error {
	if _, err := role.OnlineKeyRole(); err != nil {
		return err
	}
	current, err := os.ReadFile(l.RootPath(role))
	if err != nil {
		return fmt.Errorf("read current %s root: %w", role, err)
	}
	if err := atomicWrite(l.previousRootPath(role), current, 0o644); err != nil {
		return fmt.Errorf("preserve previous %s root: %w", role, err)
	}
	return l.generate(role, random)
}
