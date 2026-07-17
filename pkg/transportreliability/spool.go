package transportreliability

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrSpoolFull    = errors.New("transport spool full")
	ErrSpoolCorrupt = errors.New("transport spool corrupt")
	ErrSpoolStale   = errors.New("transport spool record exceeded retry horizon")
)

type SpoolConfig struct {
	Dir      string
	Key      []byte
	MaxBytes int64
	MaxAge   time.Duration
}

type SpoolRecord struct {
	UID       string    `json:"uid"`
	Stream    string    `json:"stream"`
	MessageID string    `json:"message_id"`
	Payload   []byte    `json:"payload"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type EncryptedSpool struct {
	dir          string
	pendingDir   string
	tmpDir       string
	deadDir      string
	maxBytes     int64
	maxAge       time.Duration
	aead         cipher.AEAD
	mu           sync.Mutex
	afterDeliver func(SpoolRecord) error
}

func NewEncryptedSpool(config SpoolConfig) (*EncryptedSpool, error) {
	if strings.TrimSpace(config.Dir) == "" {
		return nil, fmt.Errorf("spool directory is required")
	}
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return nil, fmt.Errorf("spool encryption key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("spool encryption: %w", err)
	}
	spool := &EncryptedSpool{
		dir: config.Dir, pendingDir: filepath.Join(config.Dir, "pending"),
		tmpDir: filepath.Join(config.Dir, "tmp"), deadDir: filepath.Join(config.Dir, "deadletter"),
		maxBytes: config.MaxBytes, maxAge: config.MaxAge, aead: aead,
	}
	for _, dir := range []string{spool.dir, spool.pendingDir, spool.tmpDir, spool.deadDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create spool directory %s: %w", dir, err)
		}
	}
	if err := spool.recoverTemps(); err != nil {
		return nil, err
	}
	return spool, nil
}

func (spool *EncryptedSpool) Append(ctx context.Context, record SpoolRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	plain, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode spool record: %w", err)
	}
	nonce := make([]byte, spool.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("spool nonce: %w", err)
	}
	sealed := append(nonce, spool.aead.Seal(nil, nonce, plain, nil)...)
	if spool.maxBytes > 0 {
		used, err := spool.size()
		if err != nil {
			return err
		}
		if used+int64(len(sealed)) > spool.maxBytes {
			return ErrSpoolFull
		}
	}
	name := safeName(record.UID + "-" + record.MessageID + ".wal")
	if name == "-.wal" || name == ".wal" {
		return fmt.Errorf("spool record UID or message ID is required")
	}
	tmpPath := filepath.Join(spool.tmpDir, name+".tmp")
	finalPath := filepath.Join(spool.pendingDir, name)
	if _, err := os.Stat(finalPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check pending spool record: %w", err)
	}
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create spool record: %w", err)
	}
	writeErr := writeSyncClose(file, sealed)
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit spool record: %w", err)
	}
	return syncDirectory(spool.pendingDir)
}

func (spool *EncryptedSpool) Replay(ctx context.Context, deliver func(context.Context, SpoolRecord) error) error {
	spool.mu.Lock()
	defer spool.mu.Unlock()
	entries, err := os.ReadDir(spool.pendingDir)
	if err != nil {
		return fmt.Errorf("read spool: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal") {
			continue
		}
		path := filepath.Join(spool.pendingDir, entry.Name())
		record, err := spool.read(path)
		if err != nil {
			if moveErr := spool.quarantine(path, entry.Name(), err); moveErr != nil {
				return errors.Join(err, moveErr)
			}
			return err
		}
		if spool.maxAge > 0 && time.Since(record.CreatedAt) > spool.maxAge {
			if err := spool.quarantine(path, entry.Name(), ErrSpoolStale); err != nil {
				return errors.Join(ErrSpoolStale, err)
			}
			return ErrSpoolStale
		}
		if err := deliver(ctx, record); err != nil {
			return fmt.Errorf("replay spool record %s: %w", record.UID, err)
		}
		if spool.afterDeliver != nil {
			if err := spool.afterDeliver(record); err != nil {
				return fmt.Errorf("after replay delivery %s: %w", record.UID, err)
			}
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove delivered spool record: %w", err)
		}
	}
	return syncDirectory(spool.pendingDir)
}

func (spool *EncryptedSpool) read(path string) (SpoolRecord, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return SpoolRecord{}, fmt.Errorf("read encrypted spool record: %w", err)
	}
	if len(sealed) <= spool.aead.NonceSize() {
		return SpoolRecord{}, ErrSpoolCorrupt
	}
	nonce := sealed[:spool.aead.NonceSize()]
	ciphertext := sealed[spool.aead.NonceSize():]
	plain, err := spool.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return SpoolRecord{}, ErrSpoolCorrupt
	}
	var record SpoolRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		return SpoolRecord{}, ErrSpoolCorrupt
	}
	return record, nil
}

func (spool *EncryptedSpool) quarantine(path, name string, cause error) error {
	target := filepath.Join(spool.deadDir, name+"."+safeName(cause.Error()))
	if err := os.Rename(path, target); err != nil {
		return fmt.Errorf("quarantine spool record: %w", err)
	}
	return syncDirectory(spool.deadDir)
}
