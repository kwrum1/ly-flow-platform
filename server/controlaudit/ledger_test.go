package controlaudit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendBatchSignsOrderedHashChainAndRedactsSecrets(t *testing.T) {
	// Given
	ledger, _ := newTestLedger(t, nil)
	entries := []Entry{
		{Actor: "admin", Action: "policy.update", Resource: "policy-1", Result: "success", Fields: map[string]interface{}{"token": "secret-value", "safe": "visible"}},
		{Actor: "admin", Action: "rule.activate", Resource: "bundle-2", Result: "success"},
	}

	// When
	batch, err := ledger.Append(context.Background(), entries)

	// Then
	if err != nil {
		t.Fatalf("append audit batch: %v", err)
	}
	if len(batch.Records) != 2 || batch.Records[0].Sequence != 1 || batch.Records[1].Sequence != 2 {
		t.Fatalf("unexpected ordered records: %#v", batch.Records)
	}
	if batch.Records[1].PreviousHash != batch.Records[0].Hash {
		t.Fatal("second record must chain to first record hash")
	}
	if got := batch.Records[0].Fields["token"]; got != "***REDACTED***" {
		t.Fatalf("token=%v, want redacted", got)
	}
	if strings.Contains(string(batch.CanonicalJSON), "secret-value") {
		t.Fatal("canonical audit batch contains secret material")
	}
	if err := ledger.Verify(context.Background()); err != nil {
		t.Fatalf("verify audit ledger: %v", err)
	}
}

func TestVerifyDetectsTamperedRecordAndEmitsHealthAlert(t *testing.T) {
	// Given
	alerts := make([]HealthAlert, 0, 1)
	ledger, dir := newTestLedger(t, func(alert HealthAlert) { alerts = append(alerts, alert) })
	batch, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.update", Resource: "policy-1", Result: "success"}})
	if err != nil {
		t.Fatalf("append audit batch: %v", err)
	}
	path := filepath.Join(dir, "batches", batch.ID+".json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit batch: %v", err)
	}
	tampered := strings.Replace(string(contents), "policy.update", "policy.delete", 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("tamper audit batch: %v", err)
	}

	// When
	err = ledger.Verify(context.Background())

	// Then
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("error=%v, want ErrIntegrity", err)
	}
	if len(alerts) != 1 || alerts[0].Code != HealthIntegrityFailure {
		t.Fatalf("health alerts=%#v", alerts)
	}
}

func TestVerifyDetectsTamperedAnchor(t *testing.T) {
	// Given
	ledger, dir := newTestLedger(t, nil)
	batch, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "rule.activate", Resource: "bundle-1", Result: "success"}})
	if err != nil {
		t.Fatalf("append audit batch: %v", err)
	}
	path := filepath.Join(dir, "anchors", batch.ID+".json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit anchor: %v", err)
	}
	contents[len(contents)-2] ^= 1
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("tamper audit anchor: %v", err)
	}

	// When
	err = ledger.Verify(context.Background())

	// Then
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("error=%v, want ErrIntegrity", err)
	}
}

func TestQueryRejectsViewerAndAllowsAuditor(t *testing.T) {
	// Given
	ledger, _ := newTestLedger(t, nil)
	if _, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.update", Resource: "policy-1", Result: "success"}}); err != nil {
		t.Fatalf("append audit batch: %v", err)
	}

	// When
	_, viewerErr := ledger.Query(context.Background(), QueryViewer)
	entries, auditorErr := ledger.Query(context.Background(), QueryAuditor)

	// Then
	if !errors.Is(viewerErr, ErrQueryForbidden) {
		t.Fatalf("viewer error=%v, want ErrQueryForbidden", viewerErr)
	}
	if auditorErr != nil || len(entries) != 1 {
		t.Fatalf("auditor query entries=%d error=%v", len(entries), auditorErr)
	}
}

func newTestLedger(t *testing.T, health func(HealthAlert)) (*Ledger, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate audit signer: %v", err)
	}
	dir := t.TempDir()
	ledger, err := NewLedger(Config{
		Dir:       dir,
		Signer:    privateKey,
		PublicKey: publicKey,
		Now:       func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) },
		Health:    health,
	})
	if err != nil {
		t.Fatalf("create audit ledger: %v", err)
	}
	return ledger, dir
}
