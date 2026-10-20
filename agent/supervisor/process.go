package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s stdout pipe: %w", process.config.Name, err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("%s stderr pipe: %w", process.config.Name, err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("%s start: %w", process.config.Name, err)
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		process.scan(stdout)
	}()
	go func() {
		defer readers.Done()
		process.scan(stderr)
	}()
	err = command.Wait()
	readers.Wait()
	if ctx.Err() != nil {
		return nil
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

func (process *Process) scan(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1<<20)
	for scanner.Scan() {
		if process.config.Logger != nil {
			process.config.Logger(fmt.Sprintf("[%s] %s", process.config.Name, scanner.Text()))
		}
	}
}
