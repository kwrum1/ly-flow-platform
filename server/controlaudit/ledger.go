package controlaudit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/lyflow/ly-flow-platform/server/security"
)

type Ledger struct {
	dir                string
	sign               func([]byte) []byte
	publicKey          ed25519.PublicKey
	now                func() time.Time
	health             func(HealthAlert)
	beforeAnchorCommit func() error
	beforePruneDelete  func() error
}

func NewLedger(config Config) (*Ledger, error) {
	if config.Dir == "" || len(config.Signer) != ed25519.PrivateKeySize && config.Sign == nil || len(config.PublicKey) != ed25519.PublicKeySize || config.Now == nil {
		return nil, errors.New("controlaudit: invalid ledger configuration")
	}
	sign := config.Sign
	if sign == nil {
		sign = func(payload []byte) []byte { return ed25519.Sign(config.Signer, payload) }
	}
	for _, directory := range []string{config.Dir, filepath.Join(config.Dir, "batches"), filepath.Join(config.Dir, "anchors")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create audit directory: %w", err)
		}
	}
	return &Ledger{dir: config.Dir, sign: sign, publicKey: config.PublicKey, now: config.Now, health: config.Health}, nil
}

func (l *Ledger) Append(ctx context.Context, entries []Entry) (Batch, error) {
	if err := ctx.Err(); err != nil {
		return Batch{}, fmt.Errorf("append audit batch: %w", err)
	}
	anchors, err := l.loadAnchors()
	if err != nil {
		return Batch{}, err
	}
	previousAnchorHash := ""
	previousBatchHash := ""
	batchSequence := uint64(len(anchors) + 1)
	if len(anchors) > 0 {
		previous := anchors[len(anchors)-1]
		previousAnchorHash, err = hashAnchor(previous)
		if err != nil {
			return Batch{}, err
		}
		previousBatchHash = previous.BatchHash
	}
	batch, err := l.buildBatch(batchSequence, previousBatchHash, entries)
	if err != nil {
		return Batch{}, err
	}
	batchPath := filepath.Join(l.dir, "batches", batch.ID+".json")
	if err := atomicWrite(batchPath, batch.CanonicalJSON, 0o600, nil); err != nil {
		return Batch{}, fmt.Errorf("write audit batch: %w", err)
	}
	createdAt := l.now().UTC()
	unsigned := anchor{BatchID: batch.ID, BatchHash: batch.Hash, PreviousAnchorHash: previousAnchorHash, CreatedAt: createdAt}
	signaturePayload, err := canonicalAnchor(unsigned)
	if err != nil {
		return Batch{}, err
	}
	unsigned.Signature = hex.EncodeToString(l.sign(signaturePayload))
	anchorJSON, err := json.Marshal(unsigned)
	if err != nil {
		return Batch{}, fmt.Errorf("marshal audit anchor: %w", err)
	}
	anchorPath := filepath.Join(l.dir, "anchors", batch.ID+".json")
	if err := atomicWrite(anchorPath, anchorJSON, 0o600, l.beforeAnchorCommit); err != nil {
		return Batch{}, fmt.Errorf("commit audit anchor: %w", err)
	}
	return batch, nil
}

func (l *Ledger) buildBatch(sequence uint64, previousBatchHash string, entries []Entry) (Batch, error) {
	records := make([]Record, 0, len(entries))
	previousRecordHash := previousBatchHash
	for index, entry := range entries {
		if entry.Actor == "" || entry.Action == "" || entry.Resource == "" || entry.Result == "" {
			return Batch{}, errors.New("controlaudit: incomplete audit entry")
		}
		record := Record{Sequence: uint64(index + 1), Actor: entry.Actor, Action: entry.Action, Resource: entry.Resource, Result: entry.Result, Fields: security.RedactMap(entry.Fields), OccurredAt: l.now().UTC(), PreviousHash: previousRecordHash}
		hash, err := hashRecord(record)
		if err != nil {
			return Batch{}, err
		}
		record.Hash = hash
		previousRecordHash = hash
		records = append(records, record)
	}
	batch := Batch{ID: fmt.Sprintf("%020d", sequence), Records: records, PreviousBatchHash: previousBatchHash}
	hash, err := hashBatch(batch)
	if err != nil {
		return Batch{}, err
	}
	batch.Hash = hash
	batch.CanonicalJSON, err = json.Marshal(batch)
	if err != nil {
		return Batch{}, fmt.Errorf("marshal audit batch: %w", err)
	}
	return batch, nil
}

func (l *Ledger) loadAnchors() ([]anchor, error) {
	paths, err := filepath.Glob(filepath.Join(l.dir, "anchors", "*.json"))
	if err != nil {
		return nil, fmt.Errorf("list audit anchors: %w", err)
	}
	sort.Strings(paths)
	anchors := make([]anchor, 0, len(paths))
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read audit anchor: %w", err)
		}
		var item anchor
		if err := json.Unmarshal(contents, &item); err != nil {
			return nil, fmt.Errorf("decode audit anchor: %w", err)
		}
		anchors = append(anchors, item)
	}
	return anchors, nil
}

func hashRecord(record Record) (string, error) {
	record.Hash = ""
	contents, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("marshal audit record: %w", err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]), nil
}

func hashBatch(batch Batch) (string, error) {
	batch.Hash = ""
	batch.CanonicalJSON = nil
	contents, err := json.Marshal(batch)
	if err != nil {
		return "", fmt.Errorf("marshal audit batch hash: %w", err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalAnchor(item anchor) ([]byte, error) {
	item.Signature = ""
	contents, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("marshal audit anchor payload: %w", err)
	}
	return contents, nil
}

func hashAnchor(item anchor) (string, error) {
	contents, err := json.Marshal(item)
	if err != nil {
		return "", fmt.Errorf("marshal audit anchor hash: %w", err)
	}
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]), nil
}
