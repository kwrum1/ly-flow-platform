package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
)

const (
	defaultLocalMirrorWatchdogPath = "/opt/ly-agent/data/local-mirror-capture.watchdog"
	localMirrorWatchdogMaxAge      = 2 * time.Minute
	localMirrorWatchdogWritePeriod = 30 * time.Second
)

type afPacketReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type localMirrorWatchdog interface {
	Activate() error
	Refresh() error
	Invalidate() error
}

type captureAttemptCallbacks struct {
	Ready      func(context.Context) error
	BeforeRead func(context.Context) error
	OnTimeout  func()
	OnPacket   func([]byte, gopacket.CaptureInfo) error
}

type localMirrorCaptureWatchdog struct {
	path        string
	clock       trafficClock
	mu          sync.Mutex
	lastWritten time.Time
}

type inactiveLocalMirrorWatchdog struct{}

func (inactiveLocalMirrorWatchdog) Activate() error   { return nil }
func (inactiveLocalMirrorWatchdog) Refresh() error    { return nil }
func (inactiveLocalMirrorWatchdog) Invalidate() error { return nil }

func localMirrorWatchdogPath() string {
	if path := os.Getenv("LOCAL_MIRROR_WATCHDOG_PATH"); path != "" {
		return path
	}
	return defaultLocalMirrorWatchdogPath
}

func checkLocalMirrorCaptureHealth(path string, clock trafficClock) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("local mirror capture watchdog is unavailable")
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("local mirror capture watchdog is invalid")
	}
	age := clock.Now().UTC().Sub(info.ModTime().UTC())
	if age < 0 || age > localMirrorWatchdogMaxAge {
		return fmt.Errorf("local mirror capture watchdog is stale")
	}
	return nil
}

func runHealthcheckSubcommand(args []string, path string, clock trafficClock) (bool, error) {
	if len(args) == 0 || args[0] != "healthcheck" {
		return false, nil
	}
	if len(args) != 2 || args[1] != "local-mirror" {
		return true, fmt.Errorf("unsupported healthcheck")
	}
	return true, checkLocalMirrorCaptureHealth(path, clock)
}

func newLocalMirrorCaptureWatchdog(path string, clock trafficClock) *localMirrorCaptureWatchdog {
	return &localMirrorCaptureWatchdog{path: path, clock: clock}
}

func (watchdog *localMirrorCaptureWatchdog) Activate() error {
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	return watchdog.write(watchdog.clock.Now().UTC())
}

func (watchdog *localMirrorCaptureWatchdog) Refresh() error {
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	now := watchdog.clock.Now().UTC()
	if !watchdog.lastWritten.IsZero() && now.Sub(watchdog.lastWritten) < localMirrorWatchdogWritePeriod {
		return nil
	}
	return watchdog.write(now)
}

func (watchdog *localMirrorCaptureWatchdog) Invalidate() error {
	watchdog.mu.Lock()
	defer watchdog.mu.Unlock()
	watchdog.lastWritten = time.Time{}
	if err := os.Remove(watchdog.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove local mirror capture watchdog: %w", err)
	}
	return nil
}

func (watchdog *localMirrorCaptureWatchdog) write(now time.Time) (err error) {
	temp, err := os.CreateTemp(filepath.Dir(watchdog.path), "."+filepath.Base(watchdog.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create local mirror capture watchdog: %w", err)
	}
	tempPath := temp.Name()
	closed := false
	renamed := false
	defer func() {
		if !closed {
			err = errors.Join(err, temp.Close())
		}
		if !renamed {
			removeErr := os.Remove(tempPath)
			if removeErr != nil && !os.IsNotExist(removeErr) {
				err = errors.Join(err, removeErr)
			}
		}
	}()

	if _, err := temp.Write([]byte("ready\n")); err != nil {
		return fmt.Errorf("write local mirror capture watchdog: %w", err)
	}
	if err := os.Chtimes(tempPath, now, now); err != nil {
		return fmt.Errorf("timestamp local mirror capture watchdog: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync local mirror capture watchdog: %w", err)
	}
	closeErr := temp.Close()
	closed = true
	if closeErr != nil {
		return fmt.Errorf("close local mirror capture watchdog: %w", closeErr)
	}
	if err := os.Rename(tempPath, watchdog.path); err != nil {
		return fmt.Errorf("replace local mirror capture watchdog: %w", err)
	}
	renamed = true
	watchdog.lastWritten = now
	return nil
}

func runAFPacketCaptureAttempt(ctx context.Context, reader afPacketReader, watchdog localMirrorWatchdog, callbacks captureAttemptCallbacks) (err error) {
	if err := callbacks.Ready(ctx); err != nil {
		return err
	}
	if err := watchdog.Activate(); err != nil {
		return fmt.Errorf("activate local mirror capture watchdog: %w", err)
	}
	defer func() {
		err = errors.Join(err, watchdog.Invalidate())
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if callbacks.BeforeRead != nil {
			if err := callbacks.BeforeRead(ctx); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		data, captureInfo, err := reader.ReadPacketData()
		if err != nil {
			var timeout interface{ Timeout() bool }
			if errors.As(err, &timeout) && timeout.Timeout() {
				if err := watchdog.Refresh(); err != nil {
					return fmt.Errorf("refresh local mirror capture watchdog: %w", err)
				}
				if callbacks.OnTimeout != nil {
					callbacks.OnTimeout()
				}
				continue
			}
			return err
		}
		if err := watchdog.Refresh(); err != nil {
			return fmt.Errorf("refresh local mirror capture watchdog: %w", err)
		}
		if err := callbacks.OnPacket(data, captureInfo); err != nil {
			return err
		}
	}
}
