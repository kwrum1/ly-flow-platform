package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentTrafficCountUsesVerifiedSignedLedger(t *testing.T) {
	// Given
	directory := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	ledger, err := json.Marshal(trafficCountLedger{SchemaVersion: "lyflow.signed-traffic-provenance/v1", Status: "active", SignatureCount: 8405})
	if err != nil {
		t.Fatalf("encode ledger: %v", err)
	}
	ledgerPath := filepath.Join(directory, "active-traffic-ledger.json")
	signaturePath := filepath.Join(directory, "active-traffic-ledger.sig")
	rootPath := filepath.Join(directory, "provenance-root.pem")
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	for path, contents := range map[string][]byte{
		ledgerPath: ledger, signaturePath: ed25519.Sign(privateKey, ledger),
		rootPath: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}
	t.Setenv("TRAFFIC_PROVENANCE_LEDGER", ledgerPath)
	t.Setenv("TRAFFIC_PROVENANCE_SIGNATURE", signaturePath)
	t.Setenv("TRAFFIC_PROVENANCE_ROOT", rootPath)

	// When
	metric, metricErr := currentTrafficCount(14, 1)

	// Then
	if metricErr != nil || metric.SignatureCount != 8405 || metric.RuleFileCount != 1 || metric.Source != "signed_active_ledger" || metric.LedgerDigest == "" {
		t.Fatalf("traffic count metric=%#v error=%v", metric, metricErr)
	}
	if err := os.WriteFile(signaturePath, make([]byte, ed25519.SignatureSize), 0o600); err != nil {
		t.Fatalf("tamper signature fixture: %v", err)
	}
	if _, err := currentTrafficCount(14, 1); err == nil {
		t.Fatal("tampered signed ledger was accepted")
	}
}
