package engine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrBundleDigest      = errors.New("security-engine: bundle digest mismatch")
	ErrLifecycleManifest = errors.New("security-engine: lifecycle manifest verification failed")
)

type LifecycleManifest struct {
	SchemaVersion     string    `json:"schema_version"`
	Revision          string    `json:"revision"`
	Digest            string    `json:"digest"`
	BundlePath        string    `json:"bundle_path"`
	SourceURL         string    `json:"source_url"`
	SourceRevision    string    `json:"source_revision"`
	ActivatedAt       time.Time `json:"activated_at"`
	PreviousRevision  string    `json:"previous_revision,omitempty"`
	SignerFingerprint string    `json:"signer_fingerprint"`
	Signature         string    `json:"signature"`
	ManifestPath      string    `json:"-"`
}

type bundleFile struct {
	Version string        `json:"version"`
	Rules   []RuntimeRule `json:"rules"`
}

func LoadLifecycleBundle(manifestPath, trustRootPath, bundleRoot string) (*Bundle, LifecycleManifest, error) {
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, LifecycleManifest{}, fmt.Errorf("inspect lifecycle manifest: %w", err)
	}
	if manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() {
		return nil, LifecycleManifest{}, ErrLifecycleManifest
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, LifecycleManifest{}, fmt.Errorf("read lifecycle manifest: %w", err)
	}
	manifest, err := decodeLifecycleManifest(manifestData)
	if err != nil {
		return nil, LifecycleManifest{}, err
	}
	if err := verifyLifecycleManifest(manifest, trustRootPath); err != nil {
		return nil, LifecycleManifest{}, err
	}
	bundlePath, err := resolveBundlePath(manifest.BundlePath, bundleRoot)
	if err != nil {
		return nil, LifecycleManifest{}, err
	}
	bundleInfo, err := os.Lstat(bundlePath)
	if err != nil {
		return nil, LifecycleManifest{}, fmt.Errorf("inspect lifecycle bundle: %w", err)
	}
	if bundleInfo.Mode()&os.ModeSymlink != 0 || !bundleInfo.Mode().IsRegular() {
		return nil, LifecycleManifest{}, ErrLifecycleManifest
	}
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, LifecycleManifest{}, fmt.Errorf("read lifecycle bundle: %w", err)
	}
	expected, err := hex.DecodeString(manifest.Digest)
	if err != nil || len(expected) != sha256.Size {
		return nil, LifecycleManifest{}, ErrBundleDigest
	}
	digest := sha256.Sum256(bundleData)
	if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return nil, LifecycleManifest{}, ErrBundleDigest
	}
	bundle, err := decodeBundle(bundleData)
	if err != nil {
		return nil, LifecycleManifest{}, err
	}
	if bundle.Version != manifest.Revision {
		return nil, LifecycleManifest{}, fmt.Errorf("bundle revision %q does not match manifest %q: %w", bundle.Version, manifest.Revision, ErrLifecycleManifest)
	}
	bundle.Digest = manifest.Digest
	manifest.ManifestPath = manifestPath
	manifest.BundlePath = bundlePath
	return bundle, manifest, nil
}

func decodeLifecycleManifest(data []byte) (LifecycleManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest LifecycleManifest
	if err := decoder.Decode(&manifest); err != nil {
		return LifecycleManifest{}, fmt.Errorf("decode lifecycle manifest: %w: %w", err, ErrLifecycleManifest)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return LifecycleManifest{}, fmt.Errorf("trailing lifecycle manifest data: %w", ErrLifecycleManifest)
	}
	if manifest.SchemaVersion != "lyflow.rule-manifest/v1" || manifest.Revision == "" || manifest.SourceRevision != manifest.Revision || manifest.BundlePath == "" || manifest.Digest == "" || manifest.SignerFingerprint == "" || manifest.Signature == "" || manifest.ActivatedAt.IsZero() {
		return LifecycleManifest{}, ErrLifecycleManifest
	}
	return manifest, nil
}

func verifyLifecycleManifest(manifest LifecycleManifest, trustRootPath string) error {
	rootPEM, err := os.ReadFile(trustRootPath)
	if err != nil {
		return fmt.Errorf("read rule trust root: %w: %w", err, ErrLifecycleManifest)
	}
	block, rest := pem.Decode(rootPEM)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return ErrLifecycleManifest
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse rule trust root: %w", ErrLifecycleManifest)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return ErrLifecycleManifest
	}
	fingerprint := sha256.Sum256(publicKey)
	expectedFingerprint, err := hex.DecodeString(manifest.SignerFingerprint)
	if err != nil || subtle.ConstantTimeCompare(fingerprint[:], expectedFingerprint) != 1 {
		return ErrLifecycleManifest
	}
	signature, err := hex.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrLifecycleManifest
	}
	unsigned := manifest
	unsigned.Signature = ""
	unsigned.ManifestPath = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal lifecycle verification payload: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrLifecycleManifest
	}
	return nil
}

func resolveBundlePath(signedPath, bundleRoot string) (string, error) {
	root, err := filepath.Abs(bundleRoot)
	if err != nil {
		return "", fmt.Errorf("resolve bundle root: %w", err)
	}
	candidate := signedPath
	if !filepath.IsAbs(candidate) {
		candidate = filepath.FromSlash(strings.TrimPrefix(filepath.ToSlash(candidate), "rules/"))
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve lifecycle bundle: %w", err)
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("lifecycle bundle escapes configured root: %w", ErrLifecycleManifest)
	}
	return candidate, nil
}

func decodeBundle(data []byte) (*Bundle, error) {
	var file bundleFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode rule bundle: %w", err)
	}
	if file.Version == "" {
		file.Version = "unknown"
	}
	return NewBundle(file.Version, file.Rules)
}
