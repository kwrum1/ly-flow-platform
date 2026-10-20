// Package lyprobe wires the ly_probe/nProbe-compatible sensor into the
// ly-agent supervisor. The C++ probe stays an external process; LyFlow owns
// configuration validation, lifecycle and capture diagnostics.
package lyprobe

import (
	"errors"
	"strings"

	"ly-flow-platform/agent/supervisor"
)

const defaultBinaryPath = "/opt/lyflow/bin/lyprobe"

var ErrInterfaceRequired = errors.New("lyprobe: interface is required")

type Config struct {
	BinaryPath string
	Interface  string
	Collector  string
	ExtraArgs  []string
	Env        []string
	Dir        string
	Logger     func(string)
}

func CommandArgs(config Config) ([]string, error) {
	if strings.TrimSpace(config.Interface) == "" {
		return nil, ErrInterfaceRequired
	}
	args := []string{"-i", strings.TrimSpace(config.Interface)}
	if strings.TrimSpace(config.Collector) != "" {
		args = append(args, "-n", strings.TrimSpace(config.Collector))
	}
	args = append(args, config.ExtraArgs...)
	return args, nil
}

func New(config Config) (*supervisor.Process, error) {
	args, err := CommandArgs(config)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(config.BinaryPath)
	if path == "" {
		path = defaultBinaryPath
	}
	return supervisor.NewProcess(supervisor.ProcessConfig{
		Name: "lyprobe", Path: path, Args: args, Env: config.Env,
		Dir: config.Dir, Logger: config.Logger,
	})
}
