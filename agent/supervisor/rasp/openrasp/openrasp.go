// Package openrasp generates JVM/PHP attachment settings for the mature
// OpenRASP engine. LyFlow does not reimplement the RASP engine.
package openrasp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	JarPath       string
	PHPModulePath string
	Root          string
	ConfigPath    string
}

func JavaAgentArgs(config Config) ([]string, error) {
	if strings.TrimSpace(config.JarPath) == "" {
		return nil, fmt.Errorf("openrasp jar path is required")
	}
	args := []string{"-javaagent:" + config.JarPath}
	if config.Root != "" {
		args = append(args, "-Dopenrasp.root="+config.Root)
	}
	if config.ConfigPath != "" {
		args = append(args, "-Dopenrasp.config="+config.ConfigPath)
	}
	args = append(args, "-Dopenrasp.cloud.enable=false")
	return args, nil
}

func PHPIni(config Config) (string, error) {
	if strings.TrimSpace(config.PHPModulePath) == "" {
		return "", fmt.Errorf("openrasp php module path is required")
	}
	lines := []string{
		"extension=" + config.PHPModulePath,
		"openrasp.cloud.enable=0",
	}
	if config.Root != "" {
		lines = append(lines, "openrasp.root="+config.Root)
	}
	if config.ConfigPath != "" {
		lines = append(lines, "openrasp.config="+config.ConfigPath)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func Probe(config Config) error {
	if config.JarPath != "" {
		if err := fileExists(config.JarPath); err != nil {
			return fmt.Errorf("openrasp java: %w", err)
		}
	}
	if config.PHPModulePath != "" {
		if err := fileExists(config.PHPModulePath); err != nil {
			return fmt.Errorf("openrasp php: %w", err)
		}
	}
	if config.JarPath == "" && config.PHPModulePath == "" {
		return fmt.Errorf("openrasp: jar or php module path is required")
	}
	return nil
}

func fileExists(path string) error {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}
