// Package supervisor provides a small lifecycle/restart supervisor for the
// ly-agent components. Components block in Start until their context is
// canceled; the supervisor restarts them with backoff when they fail.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateRestart  State = "restarting"
	StateFailed   State = "failed"
)

type Component interface {
	Name() string
	Start(context.Context) error
}

type Config struct {
	MaxRestarts int
	Backoff     time.Duration
	MaxBackoff  time.Duration
}

func (config Config) withDefaults() Config {
	if config.MaxRestarts <= 0 {
		config.MaxRestarts = 5
	}
	if config.Backoff <= 0 {
		config.Backoff = 500 * time.Millisecond
	}
	if config.MaxBackoff <= 0 {
		config.MaxBackoff = 30 * time.Second
	}
	return config
}

type ComponentStatus struct {
	Name        string
	State       State
	Restarts    int
	LastError   string
	StartedAt   time.Time
	LastRestart time.Time
}

type Supervisor struct {
	config     Config
	components []Component

	mu      sync.RWMutex
	status  map[string]*ComponentStatus
	started bool
	wg      sync.WaitGroup
}

func New(config Config, components ...Component) *Supervisor {
	status := make(map[string]*ComponentStatus, len(components))
	for _, component := range components {
		status[component.Name()] = &ComponentStatus{Name: component.Name(), State: StateStopped}
	}
	return &Supervisor{
		config:     config.withDefaults(),
		components: append([]Component(nil), components...),
		status:     status,
	}
}

func (supervisor *Supervisor) Run(ctx context.Context) error {
	if supervisor == nil {
		return errors.New("supervisor is nil")
	}
	supervisor.mu.Lock()
	if supervisor.started {
		supervisor.mu.Unlock()
		return errors.New("supervisor already started")
	}
	supervisor.started = true
	for _, component := range supervisor.components {
		name := component.Name()
		supervisor.status[name] = &ComponentStatus{Name: name, State: StateStarting}
	}
	supervisor.mu.Unlock()

	for _, component := range supervisor.components {
		supervisor.wg.Add(1)
		go supervisor.runComponent(ctx, component)
	}
	<-ctx.Done()
	supervisor.wg.Wait()
	return ctx.Err()
}

func (supervisor *Supervisor) Status() []ComponentStatus {
	supervisor.mu.RLock()
	defer supervisor.mu.RUnlock()
	result := make([]ComponentStatus, 0, len(supervisor.status))
	for _, component := range supervisor.components {
		if status, ok := supervisor.status[component.Name()]; ok {
			result = append(result, *status)
		}
	}
	return result
}

func (supervisor *Supervisor) runComponent(ctx context.Context, component Component) {
	defer supervisor.wg.Done()
	name := component.Name()
	backoff := supervisor.config.Backoff
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			supervisor.setStatus(name, StateStopped, attempt, nil)
			return
		}
		supervisor.setStatus(name, StateRunning, attempt, nil)
		err := component.Start(ctx)
		if ctx.Err() != nil {
			supervisor.setStatus(name, StateStopped, attempt, nil)
			return
		}
		if err == nil {
			supervisor.setStatus(name, StateStopped, attempt, nil)
			return
		}
		if attempt >= supervisor.config.MaxRestarts {
			supervisor.setStatus(name, StateFailed, attempt, err)
			return
		}
		supervisor.setStatus(name, StateRestart, attempt, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			supervisor.setStatus(name, StateStopped, attempt, nil)
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > supervisor.config.MaxBackoff {
			backoff = supervisor.config.MaxBackoff
		}
	}
}

func (supervisor *Supervisor) setStatus(name string, state State, restarts int, err error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	status, ok := supervisor.status[name]
	if !ok {
		status = &ComponentStatus{Name: name}
		supervisor.status[name] = status
	}
	now := time.Now().UTC()
	if state == StateRunning && status.StartedAt.IsZero() {
		status.StartedAt = now
	}
	if state == StateRestart || (state == StateRunning && restarts > 0) {
		status.LastRestart = now
	}
	status.State = state
	status.Restarts = restarts
	if err != nil {
		status.LastError = err.Error()
	} else if state == StateRunning || state == StateStopped {
		status.LastError = ""
	}
}

func (status ComponentStatus) String() string {
	return fmt.Sprintf("%s state=%s restarts=%d error=%s", status.Name, status.State, status.Restarts, status.LastError)
}
