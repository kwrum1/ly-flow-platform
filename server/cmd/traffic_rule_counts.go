package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
)

type trafficCountMetric struct {
	SignatureCount int    `json:"signature_count"`
	RuleFileCount  int    `json:"rule_file_count"`
	Source         string `json:"source"`
	LedgerDigest   string `json:"ledger_digest,omitempty"`
}

type trafficCountLedger struct {
	SchemaVersion  string `json:"schema_version"`
	Status         string `json:"status"`
	SignatureCount int    `json:"signature_count"`
}

func currentTrafficCount(scannedSignatures, ruleFiles int) (trafficCountMetric, error) {
	ledgerPath := strings.TrimSpace(os.Getenv("TRAFFIC_PROVENANCE_LEDGER"))
	if ledgerPath == "" {
		return trafficCountMetric{SignatureCount: scannedSignatures, RuleFileCount: ruleFiles, Source: "filesystem_scan"}, nil
	}
	contents, err := os.ReadFile(ledgerPath)
	if err != nil {
		return trafficCountMetric{}, fmt.Errorf("read traffic provenance ledger: %w", err)
	}
	signaturePath := firstNonEmpty(os.Getenv("TRAFFIC_PROVENANCE_SIGNATURE"), strings.TrimSuffix(ledgerPath, filepath.Ext(ledgerPath))+".sig")
	rootPath := firstNonEmpty(os.Getenv("TRAFFIC_PROVENANCE_ROOT"), filepath.Join(filepath.Dir(ledgerPath), "provenance-root.pem"))
	signature, err := os.ReadFile(signaturePath)
	if err != nil {
		return trafficCountMetric{}, fmt.Errorf("read traffic provenance signature: %w", err)
	}
	root, err := os.ReadFile(rootPath)
	if err != nil {
		return trafficCountMetric{}, fmt.Errorf("read traffic provenance root: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil {
		return trafficCountMetric{}, errors.New("traffic provenance root is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return trafficCountMetric{}, fmt.Errorf("parse traffic provenance root: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(publicKey, contents, signature) {
		return trafficCountMetric{}, errors.New("traffic provenance signature verification failed")
	}
	var ledger trafficCountLedger
	if err := json.Unmarshal(contents, &ledger); err != nil {
		return trafficCountMetric{}, fmt.Errorf("decode traffic provenance ledger: %w", err)
	}
	if ledger.SchemaVersion != "lyflow.signed-traffic-provenance/v1" || ledger.Status != "active" || ledger.SignatureCount <= 0 {
		return trafficCountMetric{}, errors.New("traffic provenance count contract is invalid")
	}
	digest := sha256.Sum256(contents)
	return trafficCountMetric{SignatureCount: ledger.SignatureCount, RuleFileCount: ruleFiles, Source: "signed_active_ledger", LedgerDigest: hex.EncodeToString(digest[:])}, nil
}

func activeLifecycleTrafficCount(ctx context.Context, manager *rulelifecycle.Manager, scannedSignatures, ruleFiles int) (trafficCountMetric, error) {
	if manager == nil {
		return currentTrafficCount(scannedSignatures, ruleFiles)
	}
	counts, err := manager.ActiveRuleCounts(ctx)
	if err != nil {
		return trafficCountMetric{}, fmt.Errorf("read verified active traffic count: %w", err)
	}
	manifest, err := manager.Active(ctx)
	if err != nil {
		return trafficCountMetric{}, fmt.Errorf("read verified active traffic manifest: %w", err)
	}
	return trafficCountMetric{SignatureCount: counts["traffic"], RuleFileCount: ruleFiles, Source: "signed_active_lifecycle", LedgerDigest: manifest.Digest}, nil
}
