package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

const (
	localMirrorHealthMaxAge       = 2 * time.Minute
	localMirrorWatchdogWriteEvery = 30 * time.Second
)

func TestLocalMirrorHealthCheckerRequiresFreshRegularNonemptyWatchdog(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		healthy bool
	}{
		{name: "missing", prepare: func(*testing.T, string) {}, healthy: false},
		{name: "empty", prepare: func(t *testing.T, path string) { writeLocalMirrorWatchdogFixture(t, path, nil, now) }, healthy: false},
		{name: "directory", prepare: func(t *testing.T, path string) { t.Helper(); mustMkdir(t, path) }, healthy: false},
		{name: "future", prepare: func(t *testing.T, path string) {
			writeLocalMirrorWatchdogFixture(t, path, []byte("ready\n"), now.Add(time.Nanosecond))
		}, healthy: false},
		{name: "age zero boundary", prepare: func(t *testing.T, path string) { writeLocalMirrorWatchdogFixture(t, path, []byte("ready\n"), now) }, healthy: true},
		{name: "age 120 seconds boundary", prepare: func(t *testing.T, path string) {
			writeLocalMirrorWatchdogFixture(t, path, []byte("ready\n"), now.Add(-localMirrorHealthMaxAge))
		}, healthy: true},
		{name: "stale", prepare: func(t *testing.T, path string) {
			writeLocalMirrorWatchdogFixture(t, path, []byte("ready\n"), now.Add(-localMirrorHealthMaxAge-time.Nanosecond))
		}, healthy: false},
		{name: "fresh", prepare: func(t *testing.T, path string) {
			writeLocalMirrorWatchdogFixture(t, path, []byte("ready\n"), now.Add(-time.Minute))
		}, healthy: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture-watchdog")
			test.prepare(t, path)

			// When
			err := checkLocalMirrorCaptureHealth(path, &fixedTrafficClock{now: now})

			// Then
			if (err == nil) != test.healthy {
				t.Fatalf("health error = %v, healthy = %v", err, test.healthy)
			}
		})
	}
}

func TestLocalMirrorWatchdogActivationAtomicallyReplacesExistingFile(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "capture-watchdog")
	writeLocalMirrorWatchdogFixture(t, path, []byte("old\n"), time.Date(2026, 7, 29, 7, 0, 0, 0, time.UTC))
	oldInfo := mustStat(t, path)
	watchdog := newLocalMirrorCaptureWatchdog(path, &fixedTrafficClock{now: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)})

	// When
	if err := watchdog.Activate(); err != nil {
		t.Fatalf("activate watchdog: %v", err)
	}

	// Then
	newInfo := mustStat(t, path)
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("activation rewrote the existing inode instead of atomically replacing it")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read watchdog: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("watchdog is empty")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read watchdog directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("atomic replacement left temporary files: %v", entries)
	}
}

func TestLocalMirrorWatchdogRefreshesAtMostEveryThirtySecondsUnderBusyReads(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "capture-watchdog")
	watchdog := newLocalMirrorCaptureWatchdog(path, clock)
	if err := watchdog.Activate(); err != nil {
		t.Fatalf("activate watchdog: %v", err)
	}
	initial := mustStat(t, path).ModTime()

	// When
	clock.now = clock.now.Add(localMirrorWatchdogWriteEvery - time.Nanosecond)
	for range 100 {
		if err := watchdog.Refresh(); err != nil {
			t.Fatalf("early refresh: %v", err)
		}
	}
	early := mustStat(t, path).ModTime()
	clock.now = clock.now.Add(time.Nanosecond)
	if err := watchdog.Refresh(); err != nil {
		t.Fatalf("due refresh: %v", err)
	}

	// Then
	if !early.Equal(initial) {
		t.Fatalf("busy reads refreshed before 30 seconds: initial=%s early=%s", initial, early)
	}
	if got := mustStat(t, path).ModTime(); !got.Equal(clock.now) {
		t.Fatalf("due refresh modtime = %s, want %s", got, clock.now)
	}
}

func TestLocalMirrorWatchdogInvalidatesActiveAttempt(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "capture-watchdog")
	watchdog := newLocalMirrorCaptureWatchdog(path, &fixedTrafficClock{now: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)})
	if err := watchdog.Activate(); err != nil {
		t.Fatalf("activate watchdog: %v", err)
	}

	// When
	if err := watchdog.Invalidate(); err != nil {
		t.Fatalf("invalidate watchdog: %v", err)
	}

	// Then
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("watchdog survived invalidation: %v", err)
	}
}

func TestAFPacketCaptureAttemptManagesWatchdogAcrossReadinessReadsAndExits(t *testing.T) {
	var _ afPacketReader = (*scriptedAFPacketReader)(nil)
	var _ localMirrorWatchdog = (*recordingLocalMirrorWatchdog)(nil)

	tests := []struct {
		name         string
		readyErr     error
		reads        []scriptedAFPacketRead
		callbackErr  error
		cancelPacket bool
		wantErr      error
		wantEvents   []string
		wantPackets  int
		wantReads    int
	}{
		{name: "readiness failure skips activation and invalidation", readyErr: errCaptureAttemptReadiness, wantErr: errCaptureAttemptReadiness},
		{name: "quiet timeout then terminal error refreshes without packet callback", reads: []scriptedAFPacketRead{{err: captureAttemptTimeout{}}, {err: errCaptureAttemptTerminal}}, wantErr: errCaptureAttemptTerminal, wantEvents: []string{"activate", "refresh", "invalidate"}, wantReads: 2},
		{name: "terminal read error invalidates once", reads: []scriptedAFPacketRead{{err: errCaptureAttemptTerminal}}, wantErr: errCaptureAttemptTerminal, wantEvents: []string{"activate", "invalidate"}, wantReads: 1},
		{name: "packet callback error invalidates once", reads: []scriptedAFPacketRead{{data: []byte("packet")}}, callbackErr: errCaptureAttemptCallback, wantErr: errCaptureAttemptCallback, wantEvents: []string{"activate", "refresh", "invalidate"}, wantPackets: 1, wantReads: 1},
		{name: "busy successful read reaches refresh then cancel exit invalidates once", reads: []scriptedAFPacketRead{{data: []byte("packet")}}, cancelPacket: true, wantEvents: []string{"activate", "refresh", "invalidate"}, wantPackets: 1, wantReads: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &scriptedAFPacketReader{reads: test.reads}
			watchdog := &recordingLocalMirrorWatchdog{}
			packetCalls := 0

			// When
			err := runAFPacketCaptureAttempt(ctx, reader, watchdog, captureAttemptCallbacks{
				Ready: func(context.Context) error { return test.readyErr },
				OnPacket: func([]byte, gopacket.CaptureInfo) error {
					packetCalls++
					if test.cancelPacket {
						cancel()
					}
					return test.callbackErr
				},
			})

			// Then
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("capture attempt error = %v, want %v", err, test.wantErr)
			}
			assertCaptureAttemptEvents(t, watchdog.events, test.wantEvents)
			if packetCalls != test.wantPackets || reader.calls != test.wantReads {
				t.Fatalf("packet calls = %d, reader calls = %d; want %d and %d", packetCalls, reader.calls, test.wantPackets, test.wantReads)
			}
		})
	}
}

func TestHealthcheckLocalMirrorDispatchesBeforeNormalStartup(t *testing.T) {
	// Given
	clock := &fixedTrafficClock{now: time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "capture-watchdog")
	writeLocalMirrorWatchdogFixture(t, path, []byte("ready\n"), clock.now)

	// When
	handled, err := runHealthcheckSubcommand([]string{"healthcheck", "local-mirror"}, path, clock)

	// Then
	if !handled || err != nil {
		t.Fatalf("healthcheck dispatch = handled %v error %v", handled, err)
	}
}

func writeLocalMirrorWatchdogFixture(t *testing.T, path string, content []byte, modifiedAt time.Time) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write watchdog fixture: %v", err)
	}
	if err := os.Chtimes(path, modifiedAt, modifiedAt); err != nil {
		t.Fatalf("set watchdog fixture time: %v", err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir watchdog fixture: %v", err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat watchdog: %v", err)
	}
	return info
}

var (
	errCaptureAttemptReadiness = errors.New("capture attempt not ready")
	errCaptureAttemptTerminal  = errors.New("capture read failed")
	errCaptureAttemptCallback  = errors.New("packet callback failed")
	errCaptureAttemptExhausted = errors.New("capture read script exhausted")
)

type scriptedAFPacketRead struct {
	data        []byte
	captureInfo gopacket.CaptureInfo
	err         error
}

type scriptedAFPacketReader struct {
	reads []scriptedAFPacketRead
	calls int
}

func (reader *scriptedAFPacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	reader.calls++
	if len(reader.reads) == 0 {
		return nil, gopacket.CaptureInfo{}, errCaptureAttemptExhausted
	}
	result := reader.reads[0]
	reader.reads = reader.reads[1:]
	return result.data, result.captureInfo, result.err
}

type recordingLocalMirrorWatchdog struct{ events []string }

func (watchdog *recordingLocalMirrorWatchdog) Activate() error {
	watchdog.events = append(watchdog.events, "activate")
	return nil
}
func (watchdog *recordingLocalMirrorWatchdog) Refresh() error {
	watchdog.events = append(watchdog.events, "refresh")
	return nil
}
func (watchdog *recordingLocalMirrorWatchdog) Invalidate() error {
	watchdog.events = append(watchdog.events, "invalidate")
	return nil
}

type captureAttemptTimeout struct{}

func (captureAttemptTimeout) Error() string { return "capture read timeout" }
func (captureAttemptTimeout) Timeout() bool { return true }

func assertCaptureAttemptEvents(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("watchdog events = %v, want %v", got, want)
	}
}
