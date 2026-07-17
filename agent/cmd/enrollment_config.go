package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func applyAgentIdentity(cfg *Config, values map[string]string) {
	if cfg == nil {
		return
	}
	if agentID := strings.TrimSpace(values["agent.id"]); agentID != "" {
		cfg.AgentID = agentID
	}
	if agentKey := strings.TrimSpace(values["agent.key"]); agentKey != "" {
		cfg.AgentKey = agentKey
	}
}

func persistAgentCredentials(path, agentID, agentKey string) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read agent config: %w", err)
	}
	updated := updateAgentYAML(string(data), agentID, agentKey)
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary agent config: %w", err)
	}
	tempPath := temp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure temporary agent config: %w", err)
	}
	if _, err := temp.WriteString(updated); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary agent config: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary agent config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary agent config: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace agent config: %w", err)
	}
	renamed = true
	return nil
}

func updateAgentYAML(content, agentID, agentKey string) string {
	lines := strings.Split(content, "\n")
	agentStart := -1
	agentEnd := len(lines)
	for index, line := range lines {
		trimmed := strings.TrimSpace(stripYAMLComment(line))
		if agentStart < 0 {
			if leadingSpaces(line) == 0 && trimmed == "agent:" {
				agentStart = index
			}
			continue
		}
		if trimmed != "" && leadingSpaces(line) == 0 {
			agentEnd = index
			break
		}
	}
	credentialLines := []string{
		"  id: " + strconv.Quote(agentID),
		"  key: " + strconv.Quote(agentKey),
	}
	if agentStart < 0 {
		trimmed := strings.TrimRight(content, "\n")
		if trimmed != "" {
			trimmed += "\n"
		}
		return trimmed + "agent:\n" + strings.Join(credentialLines, "\n") + "\n"
	}

	foundID := false
	foundKey := false
	for index := agentStart + 1; index < agentEnd; index++ {
		trimmed := strings.TrimSpace(stripYAMLComment(lines[index]))
		if leadingSpaces(lines[index]) != 2 {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "id:"):
			lines[index] = credentialLines[0]
			foundID = true
		case strings.HasPrefix(trimmed, "key:"):
			lines[index] = credentialLines[1]
			foundKey = true
		}
	}
	missing := make([]string, 0, 2)
	if !foundID {
		missing = append(missing, credentialLines[0])
	}
	if !foundKey {
		missing = append(missing, credentialLines[1])
	}
	lines = append(lines[:agentEnd], append(missing, lines[agentEnd:]...)...)
	return strings.Join(lines, "\n")
}

func leadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}
