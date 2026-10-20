// Package elkeidrasp generates Python/Node/Go RASP attachment settings for the
// Elkeid RASP engine.
package elkeidrasp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	PythonProbePath string
	ConfigPath      string
	Root            string
}

func PythonEnv(config Config) ([]string, error) {
	if strings.TrimSpace(config.PythonProbePath) == "" {
		return nil, fmt.Errorf("elkeid rasp python probe path is required")
	}
	env := []string{"PYTHONPATH=" + config.PythonProbePath}
	if config.ConfigPath != "" {
		env = append(env, "LYFLOW_RASP_CONFIG="+config.ConfigPath)
	}
	if config.Root != "" {
		env = append(env, "LYFLOW_RASP_ROOT="+config.Root)
	}
	env = append(env, "LYFLOW_RASP_MODE=monitor")
	return env, nil
}

func Probe(config Config) error {
	if strings.TrimSpace(config.PythonProbePath) == "" {
		return fmt.Errorf("elkeid rasp python probe path is required")
	}
	info, err := os.Stat(filepath.Clean(config.PythonProbePath))
	if err != nil {
		return fmt.Errorf("elkeid rasp python probe: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("elkeid rasp python probe must be a directory")
	}
	return nil
}
