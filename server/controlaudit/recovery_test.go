package controlaudit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInterruptedAnchorWriteLeavesPreviousLedgerVerifiable(t *testing.T) {
	// Given
	ledger, _ := newTestLedger(t, nil)
	if _, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.create", Resource: "policy-1", Result: "success"}}); err != nil {
		t.Fatalf("append initial audit batch: %v", err)
	}
	ledger.beforeAnchorCommit = func() error { return ErrWriteInterrupted }

	// When
	_, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.update", Resource: "policy-1", Result: "success"}})
	ledger.beforeAnchorCommit = nil
	verifyErr := ledger.Verify(context.Background())

	// Then
	if !errors.Is(err, ErrWriteInterrupted) {
		t.Fatalf("append error=%v, want ErrWriteInterrupted", err)
	}
	if verifyErr != nil {
		t.Fatalf("previous committed ledger must remain valid: %v", verifyErr)
	}
}

func TestBackupAndRecoverRestoresVerifiedAuditAnchors(t *testing.T) {
	// Given
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate audit signer: %v", err)
	}
	now := func() time.Time { return time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC) }
	sourceDir := t.TempDir()
	source, err := NewLedger(Config{Dir: sourceDir, Signer: privateKey, PublicKey: publicKey, Now: now})
	if err != nil {
		t.Fatalf("create source ledger: %v", err)
	}
	if _, err := source.Append(context.Background(), []Entry{{Actor: "admin", Action: "rule.activate", Resource: "bundle-1", Result: "success"}}); err != nil {
		t.Fatalf("append source audit batch: %v", err)
	}
	backupDir := filepath.Join(t.TempDir(), "backup")
	if err := source.Backup(context.Background(), backupDir); err != nil {
		t.Fatalf("backup audit ledger: %v", err)
	}
	target, err := NewLedger(Config{Dir: t.TempDir(), Signer: privateKey, PublicKey: publicKey, Now: now})
	if err != nil {
		t.Fatalf("create target ledger: %v", err)
	}

	// When
	err = target.Recover(context.Background(), backupDir)

	// Then
	if err != nil {
		t.Fatalf("recover audit ledger: %v", err)
	}
	if err := target.Verify(context.Background()); err != nil {
		t.Fatalf("verify recovered audit ledger: %v", err)
	}
}

func TestRetentionKeepsCheckpointAndRemainingChainVerifiable(t *testing.T) {
	// Given
	ledger, dir := newTestLedger(t, nil)
	first, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.create", Resource: "policy-1", Result: "success"}})
	if err != nil {
		t.Fatalf("append first audit batch: %v", err)
	}
	ledger.now = func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) }
	if _, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.update", Resource: "policy-1", Result: "success"}}); err != nil {
		t.Fatalf("append second audit batch: %v", err)
	}

	// When
	err = ledger.PruneBefore(context.Background(), time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC))

	// Then
	if err != nil {
		t.Fatalf("prune audit ledger: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "batches", first.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired batch stat error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "retention-checkpoint.json")); err != nil {
		t.Fatalf("retention checkpoint: %v", err)
	}
	if err := ledger.Verify(context.Background()); err != nil {
		t.Fatalf("verify retained ledger: %v", err)
	}
}

func TestInterruptedPruneLeavesLedgerVerifiable(t *testing.T) {
	// Given
	ledger, _ := newTestLedger(t, nil)
	if _, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.create", Resource: "policy-1", Result: "success"}}); err != nil {
		t.Fatalf("append first audit batch: %v", err)
	}
	ledger.now = func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) }
	if _, err := ledger.Append(context.Background(), []Entry{{Actor: "admin", Action: "policy.update", Resource: "policy-1", Result: "success"}}); err != nil {
		t.Fatalf("append second audit batch: %v", err)
	}
	ledger.beforePruneDelete = func() error { return ErrWriteInterrupted }

	// When
	err := ledger.PruneBefore(context.Background(), time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC))
	ledger.beforePruneDelete = nil
	verifyErr := ledger.Verify(context.Background())

	// Then
	if !errors.Is(err, ErrWriteInterrupted) {
		t.Fatalf("prune error=%v, want ErrWriteInterrupted", err)
	}
	if verifyErr != nil {
		t.Fatalf("interrupted prune must preserve verifiable state: %v", verifyErr)
	}
}
