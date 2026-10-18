package supervisor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type blockingComponent struct {
	name string
	done chan struct{}
}

func (component *blockingComponent) Name() string { return component.name }

func (component *blockingComponent) Start(ctx context.Context) error {
	<-ctx.Done()
	close(component.done)
	return nil
}

type flakyComponent struct {
	name    string
	mu      sync.Mutex
	attempt int
	running chan struct{}
}

func (component *flakyComponent) Name() string { return component.name }

func (component *flakyComponent) Start(ctx context.Context) error {
	component.mu.Lock()
	component.attempt++
	attempt := component.attempt
	component.mu.Unlock()
	if attempt < 3 {
		return errors.New("transient failure")
	}
	close(component.running)
	<-ctx.Done()
	return nil
}

type failingComponent struct {
	name string
}

func (component *failingComponent) Name() string { return component.name }

func (component *failingComponent) Start(context.Context) error {
	return errors.New("permanent failure")
}

func TestRunStopsOnContextCancel(t *testing.T) {
	component := &blockingComponent{name: "blocking", done: make(chan struct{})}
	supervisor := New(Config{}, component)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- supervisor.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
	}
	status := supervisor.Status()
	if len(status) != 1 || status[0].State != StateStopped {
		t.Fatalf("status = %+v", status)
	}
	select {
	case <-component.done:
	default:
		t.Fatal("component did not observe cancellation")
	}
}

func TestRestartsFlakyComponent(t *testing.T) {
	component := &flakyComponent{name: "flaky", running: make(chan struct{})}
	supervisor := New(Config{MaxRestarts: 5, Backoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond}, component)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- supervisor.Run(ctx) }()
	select {
	case <-component.running:
	case <-time.After(2 * time.Second):
		t.Fatal("component did not reach running state")
	}
	cancel()
	<-errCh
	status := supervisor.Status()[0]
	if status.Restarts != 2 || status.State != StateStopped {
		t.Fatalf("status = %+v", status)
	}
}

func TestMarksPermanentlyFailedComponent(t *testing.T) {
	component := &failingComponent{name: "failing"}
	supervisor := New(Config{MaxRestarts: 1, Backoff: time.Millisecond, MaxBackoff: time.Millisecond}, component)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- supervisor.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := supervisor.Status()[0]
		if status.State == StateFailed {
			if status.Restarts != 1 || status.LastError == "" {
				t.Fatalf("status = %+v", status)
			}
			cancel()
			<-errCh
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-errCh
	t.Fatalf("component never failed: %+v", supervisor.Status())
}

func TestStatusPreservesComponentOrder(t *testing.T) {
	supervisor := New(Config{}, &blockingComponent{name: "a", done: make(chan struct{})}, &blockingComponent{name: "b", done: make(chan struct{})})
	status := supervisor.Status()
	if len(status) != 2 || status[0].Name != "a" || status[1].Name != "b" {
		t.Fatalf("status = %+v", status)
	}
}
