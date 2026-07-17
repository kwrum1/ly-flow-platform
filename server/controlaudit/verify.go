package controlaudit

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (l *Ledger) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify audit ledger: %w", err)
	}
	if err := l.verify(); err != nil {
		if l.health != nil {
			l.health(HealthAlert{Code: HealthIntegrityFailure, At: l.now().UTC()})
		}
		return errors.Join(ErrIntegrity, err)
	}
	return nil
}

func (l *Ledger) verify() error {
	anchors, err := l.loadAnchors()
	if err != nil {
		return err
	}
	checkpoint, err := l.loadCheckpoint()
	if err != nil {
		return err
	}
	previousAnchorHash := checkpoint.LastPrunedAnchorHash
	previousBatchHash := checkpoint.LastPrunedBatchHash
	for _, item := range anchors {
		if checkpoint.LastPrunedBatchID != "" && item.BatchID <= checkpoint.LastPrunedBatchID {
			continue
		}
		payload, err := canonicalAnchor(item)
		if err != nil {
			return err
		}
		signature, err := hex.DecodeString(item.Signature)
		if err != nil || !ed25519.Verify(l.publicKey, payload, signature) {
			return errors.New("audit anchor signature invalid")
		}
		if item.PreviousAnchorHash != previousAnchorHash {
			return errors.New("audit anchor chain invalid")
		}
		batch, err := l.readBatch(item.BatchID)
		if err != nil {
			return err
		}
		if batch.Hash != item.BatchHash {
			return errors.New("audit anchor batch hash mismatch")
		}
		if previousBatchHash != "" && batch.PreviousBatchHash != previousBatchHash {
			return errors.New("audit batch chain invalid")
		}
		if err := verifyBatch(batch); err != nil {
			return err
		}
		previousBatchHash = batch.Hash
		previousAnchorHash, err = hashAnchor(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *Ledger) readBatch(id string) (Batch, error) {
	contents, err := os.ReadFile(filepath.Join(l.dir, "batches", id+".json"))
	if err != nil {
		return Batch{}, fmt.Errorf("read audit batch: %w", err)
	}
	var batch Batch
	if err := json.Unmarshal(contents, &batch); err != nil {
		return Batch{}, fmt.Errorf("decode audit batch: %w", err)
	}
	return batch, nil
}

func verifyBatch(batch Batch) error {
	calculatedBatchHash, err := hashBatch(batch)
	if err != nil {
		return err
	}
	if calculatedBatchHash != batch.Hash {
		return errors.New("audit batch hash invalid")
	}
	previousRecordHash := batch.PreviousBatchHash
	for index, record := range batch.Records {
		if record.Sequence != uint64(index+1) || record.PreviousHash != previousRecordHash {
			return errors.New("audit record order invalid")
		}
		calculatedRecordHash, err := hashRecord(record)
		if err != nil {
			return err
		}
		if calculatedRecordHash != record.Hash {
			return errors.New("audit record hash invalid")
		}
		previousRecordHash = record.Hash
	}
	return nil
}

func (l *Ledger) loadCheckpoint() (retentionCheckpoint, error) {
	contents, err := os.ReadFile(filepath.Join(l.dir, "retention-checkpoint.json"))
	if errors.Is(err, os.ErrNotExist) {
		return retentionCheckpoint{}, nil
	}
	if err != nil {
		return retentionCheckpoint{}, fmt.Errorf("read retention checkpoint: %w", err)
	}
	var checkpoint retentionCheckpoint
	if err := json.Unmarshal(contents, &checkpoint); err != nil {
		return retentionCheckpoint{}, fmt.Errorf("decode retention checkpoint: %w", err)
	}
	signature, err := hex.DecodeString(checkpoint.Signature)
	payload, payloadErr := canonicalCheckpoint(checkpoint)
	if err != nil || payloadErr != nil || !ed25519.Verify(l.publicKey, payload, signature) {
		return retentionCheckpoint{}, errors.New("retention checkpoint signature invalid")
	}
	return checkpoint, nil
}

func canonicalCheckpoint(checkpoint retentionCheckpoint) ([]byte, error) {
	checkpoint.Signature = ""
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("marshal retention checkpoint payload: %w", err)
	}
	return payload, nil
}
