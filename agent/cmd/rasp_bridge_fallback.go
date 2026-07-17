package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const raspFallbackSchemaVersion = "lyflow.rasp_fallback.v1"

type raspFallbackReason string

const (
	raspFallbackQueueFull      raspFallbackReason = "queue_full"
	raspFallbackDeliveryFailed raspFallbackReason = "delivery_failed"
)

type raspFallbackRecord struct {
	SchemaVersion        string                 `json:"schema_version"`
	RecordedAt           time.Time              `json:"recorded_at"`
	Reason               raspFallbackReason     `json:"reason"`
	AgentID              string                 `json:"agent_id"`
	PolicyID             string                 `json:"policy_id"`
	PolicyVersion        uint64                 `json:"policy_version"`
	EventID              string                 `json:"event_id"`
	PayloadSHA256        string                 `json:"payload_sha256"`
	PreviousRecordSHA256 string                 `json:"previous_record_sha256,omitempty"`
	RecordSHA256         string                 `json:"record_sha256"`
	Event                raspBridgeEventRequest `json:"event"`
}

type raspFallbackLog struct {
	mu       sync.Mutex
	path     string
	lastHash string
	now      func() time.Time
}

func newRASPBridgeFallbackLog(path string, now func() time.Time) (*raspFallbackLog, error) {
	if now == nil {
		return nil, errors.New("RASP fallback clock required")
	}
	log := &raspFallbackLog{path: path, now: now}
	if err := log.loadAndVerify(); err != nil {
		return nil, err
	}
	return log, nil
}

func (log *raspFallbackLog) Append(event raspBridgeEventRequest, reason raspFallbackReason) error {
	log.mu.Lock()
	defer log.mu.Unlock()
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	record := raspFallbackRecord{
		SchemaVersion: raspFallbackSchemaVersion, RecordedAt: log.now().UTC(), Reason: reason,
		AgentID: event.AgentID, PolicyID: event.PolicyID, PolicyVersion: event.PolicyVersion,
		EventID: event.EventID, PayloadSHA256: sha256Hex(payload), PreviousRecordSHA256: log.lastHash, Event: event,
	}
	record.RecordSHA256, err = raspFallbackRecordHash(record)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(log.path), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(log.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	log.lastHash = record.RecordSHA256
	return nil
}

func (log *raspFallbackLog) loadAndVerify() error {
	file, err := os.Open(log.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), raspBridgeMaxBodyBytes*2)
	previous := ""
	for scanner.Scan() {
		var record raspFallbackRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return fmt.Errorf("decode RASP fallback integrity record: %w", err)
		}
		expected, err := raspFallbackRecordHash(record)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(record.Event)
		if err != nil {
			return err
		}
		if record.SchemaVersion != raspFallbackSchemaVersion || record.PreviousRecordSHA256 != previous || record.PayloadSHA256 != sha256Hex(payload) || record.RecordSHA256 != expected {
			return errors.New("RASP fallback integrity verification failed")
		}
		previous = record.RecordSHA256
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	log.lastHash = previous
	return nil
}

func raspFallbackRecordHash(record raspFallbackRecord) (string, error) {
	record.RecordSHA256 = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return sha256Hex(encoded), nil
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
