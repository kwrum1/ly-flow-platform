// Package wazuh wires the Wazuh agent into the ly-agent supervisor.
package wazuh

import "ly-flow-platform/agent/supervisor"

const defaultBinaryPath = "/var/ossec/bin/wazuh-agentd"

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
		Name: "wazuh-agent", Path: path, Args: config.Args, Env: config.Env,
		Dir: config.Dir, Logger: config.Logger,
	})
}
