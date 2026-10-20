package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ProcessConfig describes an external, long-running component such as the
// Elkeid agent or Wazuh agent. LyFlow supervises it but does not reimplement it.
type ProcessConfig struct {
	Name   string
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Logger func(string)
}

type Process struct {
	config ProcessConfig
}

func NewProcess(config ProcessConfig) (*Process, error) {
	if strings.TrimSpace(config.Name) == "" {
		return nil, fmt.Errorf("process name is required")
	}
	if strings.TrimSpace(config.Path) == "" {
		return nil, fmt.Errorf("process path is required")
	}
	return &Process{config: config}, nil
}

func (process *Process) Name() string {
	return process.config.Name
}

func (process *Process) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	command := exec.CommandContext(ctx, process.config.Path, process.config.Args...)
	command.Dir = process.config.Dir
	if len(process.config.Env) > 0 {
		command.Env = append(os.Environ(), process.config.Env...)
	}
	writer := &processLogWriter{name: process.config.Name, logger: process.config.Logger}
	command.Stdout = writer
	command.Stderr = writer
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		return fmt.Errorf("%s start: %w", process.config.Name, err)
	}
	err := command.Wait()
	writer.flush()
	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("%s exited: %w", process.config.Name, err)
	}
	return nil
}

func (process *Process) Probe() error {
	info, err := os.Stat(process.config.Path)
	if err != nil {
		return fmt.Errorf("%s binary: %w", process.config.Name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s binary is a directory", process.config.Name)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s binary is not executable", process.config.Name)
	}
	return nil
}

type processLogWriter struct {
	name   string
	logger func(string)
	mu     sync.Mutex
	buffer []byte
}

func (writer *processLogWriter) Write(p []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.buffer = append(writer.buffer, p...)
	for {
		index := bytes.IndexByte(writer.buffer, '\n')
		if index < 0 {
			return len(p), nil
		}
		writer.emit(strings.TrimSuffix(string(writer.buffer[:index]), "\r"))
		writer.buffer = writer.buffer[index+1:]
	}
}

func (writer *processLogWriter) flush() {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.buffer) == 0 {
		return
	}
	writer.emit(strings.TrimSuffix(string(writer.buffer), "\r"))
	writer.buffer = nil
}

func (writer *processLogWriter) emit(line string) {
	if writer.logger != nil {
		writer.logger(fmt.Sprintf("[%s] %s", writer.name, line))
	}
}
