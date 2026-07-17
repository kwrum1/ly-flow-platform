package transportreliability

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetryRunsBoundedAttemptsWithDeterministicJitter(t *testing.T) {
	// Given
	policy := RetryPolicy{MaxAttempts: 3, BaseDelay: 10 * time.Millisecond, MaxDelay: 20 * time.Millisecond, Jitter: 0.25}
	delays := make([]time.Duration, 0, 2)
	attempts := 0

	// When
	err := policy.Do(context.Background(), "event-1", func(context.Context) error {
		attempts++
		return errors.New("unavailable")
	}, func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	})

	// Then
	if err == nil || attempts != 3 || len(delays) != 2 {
		t.Fatalf("retry was not bounded: attempts=%d delays=%v err=%v", attempts, delays, err)
	}
	for _, delay := range delays {
		if delay < 0 || delay > policy.MaxDelay {
			t.Fatalf("jitter escaped bounds: %s", delay)
		}
	}
}

func TestEncryptedSpoolReplayKeepsPlaintextOffDisk(t *testing.T) {
	// Given
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: dir, Key: key, MaxBytes: 1 << 20, MaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	record := SpoolRecord{UID: "evt-secret", Stream: "events:test", MessageID: "1-0", Payload: []byte(`{"token":"plaintext-secret"}`), CreatedAt: time.Now().UTC()}

	// When
	if err := spool.Append(context.Background(), record); err != nil {
		t.Fatalf("append spool: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "pending", "*.wal"))
	if err != nil || len(files) != 1 {
		t.Fatalf("pending spool file missing: %v %v", files, err)
	}
	onDisk, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	var delivered SpoolRecord
	if err := spool.Replay(context.Background(), func(_ context.Context, got SpoolRecord) error {
		delivered = got
		return nil
	}); err != nil {
		t.Fatalf("replay spool: %v", err)
	}

	// Then
	if strings.Contains(string(onDisk), "plaintext-secret") || string(delivered.Payload) != string(record.Payload) {
		t.Fatalf("spool encryption or replay failed: disk=%q delivered=%q", onDisk, delivered.Payload)
	}
	files, _ = filepath.Glob(filepath.Join(dir, "pending", "*.wal"))
	if len(files) != 0 {
		t.Fatalf("delivered spool record remained pending: %v", files)
	}
}

func TestEncryptedSpoolFullAndCorruptRecordsAreAccounted(t *testing.T) {
	// Given
	dir := t.TempDir()
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: dir, Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 32, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}

	// When
	fullErr := spool.Append(context.Background(), SpoolRecord{UID: "too-large", Payload: make([]byte, 128), CreatedAt: time.Now().UTC()})
	if err := os.WriteFile(filepath.Join(dir, "pending", "corrupt.wal"), []byte("not-ciphertext"), 0o600); err != nil {
		t.Fatalf("seed corruption: %v", err)
	}
	replayErr := spool.Replay(context.Background(), func(context.Context, SpoolRecord) error { return nil })

	// Then
	if !errors.Is(fullErr, ErrSpoolFull) || !errors.Is(replayErr, ErrSpoolCorrupt) {
		t.Fatalf("spool failures lost typed accounting: full=%v corrupt=%v", fullErr, replayErr)
	}
	quarantined, _ := filepath.Glob(filepath.Join(dir, "deadletter", "corrupt.wal.*"))
	if len(quarantined) != 1 {
		t.Fatalf("corrupt record not quarantined: %v", quarantined)
	}
}

func TestEncryptedSpoolRecoversCommittedCrashWindowTemp(t *testing.T) {
	// Given
	dir := t.TempDir()
	config := SpoolConfig{Dir: dir, Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1 << 20, MaxAge: time.Hour}
	spool, err := NewEncryptedSpool(config)
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	record := SpoolRecord{UID: "crash-window", Stream: "events:test", MessageID: "2-0", Payload: []byte("payload"), CreatedAt: time.Now().UTC()}
	if err := spool.Append(context.Background(), record); err != nil {
		t.Fatalf("append spool: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "pending", "*.wal"))
	if len(files) != 1 {
		t.Fatalf("pending record missing: %v", files)
	}
	tempPath := filepath.Join(dir, "tmp", filepath.Base(files[0])+".tmp")
	if err := os.Rename(files[0], tempPath); err != nil {
		t.Fatalf("simulate rename crash window: %v", err)
	}

	// When
	recovered, err := NewEncryptedSpool(config)
	if err != nil {
		t.Fatalf("recover spool: %v", err)
	}
	var delivered SpoolRecord
	if err := recovered.Replay(context.Background(), func(_ context.Context, got SpoolRecord) error {
		delivered = got
		return nil
	}); err != nil {
		t.Fatalf("replay recovered record: %v", err)
	}

	// Then
	if delivered.UID != record.UID || string(delivered.Payload) != "payload" {
		t.Fatalf("crash-window recovery changed record: %+v", delivered)
	}
}

func TestEncryptedSpoolRejectsStaleEncryptedRecord(t *testing.T) {
	// Given
	dir := t.TempDir()
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: dir, Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	record := SpoolRecord{UID: "stale-uid", Stream: "events:test", MessageID: "3-0", Payload: []byte("stale-plaintext"), CreatedAt: time.Now().UTC().Add(-2 * time.Hour)}
	if err := spool.Append(context.Background(), record); err != nil {
		t.Fatalf("append stale record: %v", err)
	}
	pending, err := filepath.Glob(filepath.Join(dir, "pending", "*.wal"))
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending stale record missing: %v %v", pending, err)
	}
	onDisk, err := os.ReadFile(pending[0])
	if err != nil {
		t.Fatalf("read encrypted stale record: %v", err)
	}
	deliveries := 0

	// When
	replayErr := spool.Replay(context.Background(), func(context.Context, SpoolRecord) error {
		deliveries++
		return nil
	})

	// Then
	if !errors.Is(replayErr, ErrSpoolStale) || deliveries != 0 || strings.Contains(string(onDisk), "stale-plaintext") {
		t.Fatalf("stale encrypted record was not rejected safely: err=%v deliveries=%d disk=%q", replayErr, deliveries, onDisk)
	}
}

func TestEncryptedSpoolCrashAfterDeliveryReplaysStableUID(t *testing.T) {
	// Given
	spool, err := NewEncryptedSpool(SpoolConfig{Dir: t.TempDir(), Key: []byte("0123456789abcdef0123456789abcdef"), MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("create spool: %v", err)
	}
	record := SpoolRecord{UID: "stable-event-uid", Stream: "events:test", MessageID: "native-1", Payload: []byte("payload"), CreatedAt: time.Now().UTC()}
	if err := spool.Append(context.Background(), record); err != nil {
		t.Fatalf("append record: %v", err)
	}
	crashed := false
	spool.afterDeliver = func(SpoolRecord) error {
		if !crashed {
			crashed = true
			return errors.New("simulated crash after publish")
		}
		return nil
	}
	deliveredUIDs := make([]string, 0, 2)
	deliver := func(_ context.Context, delivered SpoolRecord) error {
		deliveredUIDs = append(deliveredUIDs, delivered.UID)
		return nil
	}

	// When
	firstErr := spool.Replay(context.Background(), deliver)
	secondErr := spool.Replay(context.Background(), deliver)

	// Then
	if firstErr == nil || secondErr != nil || len(deliveredUIDs) != 2 || deliveredUIDs[0] != record.UID || deliveredUIDs[1] != record.UID {
		t.Fatalf("crash replay changed stable UID: first=%v second=%v uids=%v", firstErr, secondErr, deliveredUIDs)
	}
}

func TestAccountingInvariantIncludesUnresolvedLoss(t *testing.T) {
	// Given
	accounting := &Accounting{}

	// When
	accounting.Received()
	accounting.Lost()

	// Then
	snapshot := accounting.Snapshot()
	if !snapshot.Valid() || snapshot.Received != 1 || snapshot.Pending != 1 || snapshot.Losses != 1 {
		t.Fatalf("accounting invariant failed: %+v", snapshot)
	}
}

func TestDeterministicUIDIsStableAndNamespaced(t *testing.T) {
	// Given / When
	first := DeterministicUID("threat_events", "events:runtime", "1-0")
	second := DeterministicUID("threat_events", "events:runtime", "1-0")
	other := DeterministicUID("traffic_sessions", "events:runtime", "1-0")

	// Then
	if first == "" || first != second || first == other {
		t.Fatalf("deterministic UID contract failed: %q %q %q", first, second, other)
	}
}

func TestDeadLetterReasonRejectsArbitraryString(t *testing.T) {
	// Given / When
	_, err := ParseDeadLetterReason("operator_supplied_reason")
	permanent := Permanent(DeadLetterReason("operator_supplied_reason"), errors.New("failure"))

	// Then
	if !errors.Is(err, ErrInvalidDeadLetterReason) || !errors.Is(permanent, ErrInvalidDeadLetterReason) {
		t.Fatalf("arbitrary dead-letter reason accepted: parse=%v permanent=%v", err, permanent)
	}
}
