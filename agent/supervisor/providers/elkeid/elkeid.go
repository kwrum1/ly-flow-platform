// Package elkeid wires the Elkeid agent into the ly-agent supervisor.
// LyFlow supervises the mature Elkeid process instead of reimplementing it.
package elkeid

import (
	"ly-flow-platform/agent/supervisor"
)

const defaultBinaryPath = "/opt/elkeid/agent/elkeid-agent"

type Config struct {
	BinaryPath string
	Args       []string
	Env        []string
	Dir        string
	Logger     func(string)
}

func New(config Config) (*supervisor.Process, error) {
	path := config.BinaryPath
	if path == "" {
		path = defaultBinaryPath
	}
	return supervisor.NewProcess(supervisor.ProcessConfig{
		Name: "elkeid-agent", Path: path, Args: config.Args, Env: config.Env,
		Dir: config.Dir, Logger: config.Logger,
	})
}
