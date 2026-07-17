package controlaudit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (l *Ledger) Backup(ctx context.Context, destination string) error {
	if err := l.Verify(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return fmt.Errorf("create audit backup: %w", err)
	}
	if err := copyTree(l.dir, destination); err != nil {
		return fmt.Errorf("copy audit backup: %w", err)
	}
	return nil
}

func (l *Ledger) Recover(ctx context.Context, source string) error {
	verifier, err := NewLedger(Config{Dir: source, Sign: l.sign, PublicKey: l.publicKey, Now: l.now})
	if err != nil {
		return fmt.Errorf("open audit recovery source: %w", err)
	}
	if err := verifier.Verify(ctx); err != nil {
		return fmt.Errorf("verify audit recovery source: %w", err)
	}
	if err := copyTree(source, l.dir); err != nil {
		return fmt.Errorf("restore audit ledger: %w", err)
	}
	return nil
}

func (l *Ledger) PruneBefore(ctx context.Context, cutoff time.Time) error {
	if err := l.Verify(ctx); err != nil {
		return err
	}
	anchors, err := l.loadAnchors()
	if err != nil {
		return err
	}
	lastPrunedHash := ""
	lastPrunedBatchHash := ""
	lastPrunedBatchID := ""
	pruned := make([]anchor, 0)
	for _, item := range anchors {
		if !item.CreatedAt.Before(cutoff) {
			break
		}
		lastPrunedHash, err = hashAnchor(item)
		if err != nil {
			return err
		}
		lastPrunedBatchHash = item.BatchHash
		lastPrunedBatchID = item.BatchID
		pruned = append(pruned, item)
	}
	if lastPrunedHash == "" {
		return nil
	}
	checkpoint := retentionCheckpoint{LastPrunedAnchorHash: lastPrunedHash, LastPrunedBatchHash: lastPrunedBatchHash, LastPrunedBatchID: lastPrunedBatchID}
	payload, err := canonicalCheckpoint(checkpoint)
	if err != nil {
		return err
	}
	checkpoint.Signature = hex.EncodeToString(l.sign(payload))
	contents, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("marshal retention checkpoint: %w", err)
	}
	if err := atomicWrite(filepath.Join(l.dir, "retention-checkpoint.json"), contents, 0o600, nil); err != nil {
		return fmt.Errorf("write retention checkpoint: %w", err)
	}
	if l.beforePruneDelete != nil {
		if err := l.beforePruneDelete(); err != nil {
			return err
		}
	}
	for _, item := range pruned {
		if err := os.Remove(filepath.Join(l.dir, "anchors", item.BatchID+".json")); err != nil {
			return fmt.Errorf("remove expired audit anchor: %w", err)
		}
		if err := os.Remove(filepath.Join(l.dir, "batches", item.BatchID+".json")); err != nil {
			return fmt.Errorf("remove expired audit batch: %w", err)
		}
	}
	return nil
}
