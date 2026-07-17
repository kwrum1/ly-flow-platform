package engine

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrRuntimeCPUBudget     = errors.New("security-engine runtime CPU budget exceeded")
	ErrRuntimeWatchdogStale = errors.New("security-engine runtime watchdog stale")
)

type SnapshotError struct {
	Integrity  error
	Accounting error
}

func (err *SnapshotError) Error() string {
	return fmt.Sprintf("security-engine snapshot unavailable: %v", errors.Join(err.Integrity, err.Accounting))
}

func (err *SnapshotError) Unwrap() error {
	return errors.Join(err.Integrity, err.Accounting)
}

type RuntimeSupervisionError struct {
	Worker      error
	Publication error
}

func (err *RuntimeSupervisionError) Error() string {
	return fmt.Sprintf("security-engine supervision stopped: %v", errors.Join(err.Worker, err.Publication))
}

func (err *RuntimeSupervisionError) Unwrap() error {
	return errors.Join(err.Worker, err.Publication)
}

func (e *Engine) Supervise(ctx context.Context) error {
	var publicationErr error
	for {
		workerErr := e.runSupervisedWorker(ctx)
		if workerErr == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if publishErr := e.publishControlHealth(ctx, e.RuntimeHealth()); publishErr != nil {
			publicationErr = publishErr
		}
		if e.RecordWatchdogRestart() {
			continue
		}
		event := e.RuntimeHealth()
		if publishErr := e.publishControlHealth(ctx, event); publishErr != nil {
			publicationErr = errors.Join(publicationErr, publishErr)
		}
		return &RuntimeSupervisionError{Worker: workerErr, Publication: publicationErr}
	}
}

func (e *Engine) runSupervisedWorker(ctx context.Context) error {
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- e.Run(workerCtx)
	}()
	maxAge := e.cfg.ReadBlock + e.cfg.CPUBudget + time.Second
	if maxAge <= time.Second {
		maxAge = 2 * time.Second
	}
	ticker := time.NewTicker(maxAge / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-result
			return nil
		case err := <-result:
			return err
		case <-ticker.C:
			if e.health.checkWatchdog(maxAge) {
				continue
			}
			cancel()
			<-result
			return ErrRuntimeWatchdogStale
		}
	}
}
