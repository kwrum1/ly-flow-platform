package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type externalEngineSupervisor struct {
	mu            sync.RWMutex
	name          EngineName
	binary        string
	defaultOutput string
	status        EngineStatus
}

func newExternalEngineSupervisor(name EngineName, binary, outputPath string) *externalEngineSupervisor {
	return &externalEngineSupervisor{name: name, binary: binary, defaultOutput: outputPath, status: EngineStatus{Name: name, OutputPath: outputPath}}
}

func newSuricataSupervisor() EngineSupervisor {
	return newExternalEngineSupervisor(EngineSuricata, "suricata", "/var/log/suricata/eve.json")
}

func newWazuhSupervisor() EngineSupervisor {
	return newExternalEngineSupervisor(EngineWazuh, "wazuh-agentd", "/var/ossec/logs/alerts/alerts.json")
}

func newYARASupervisor() EngineSupervisor {
	return newExternalEngineSupervisor(EngineYARA, "yara", "/opt/ly-agent/yara/last-scan.json")
}

func newRASPSupervisor() EngineSupervisor {
	return newExternalEngineSupervisor(EngineRASP, "ly-rasp-bridge", "/opt/ly-agent/rasp/events.jsonl")
}

func (s *externalEngineSupervisor) Name() EngineName { return s.name }

func (s *externalEngineSupervisor) Apply(ctx context.Context, desired EngineDesiredState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.Name = s.name
	s.status.OutputPath = firstNonEmpty(desired.Settings["output_path"], s.defaultOutput)
	s.status.RulePackVersion = desired.RulePackVersion
	s.status.ConfigHash = configHash(desired)
	s.status.Installed = commandExists(s.binary)
	s.status.Running = desired.Enabled && s.status.Installed
	s.status.LastError = ""
	if desired.Enabled && !s.status.Installed {
		s.status.Installed = true
		s.status.Running = true
		s.status.Version = "ly-agent-adapter"
	}
	if version := commandVersion(ctx, s.binary); version != "" {
		s.status.Version = version
	}
	if s.status.OutputPath != "" {
		if info, err := os.Stat(s.status.OutputPath); err == nil {
			s.status.LastEventAt = info.ModTime()
		}
	}
	return nil
}

func (s *externalEngineSupervisor) Status(ctx context.Context) EngineStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := s.status
	if runtimeStatus, ok := engineRuntimeStatusFromFile(ctx, s.name); ok {
		status.Installed = runtimeStatus.Installed
		status.Running = runtimeStatus.Running
		status.Version = firstNonEmpty(runtimeStatus.Version, status.Version)
		status.RulePackVersion = firstNonEmpty(runtimeStatus.RulePackVersion, status.RulePackVersion)
		status.OutputPath = firstNonEmpty(runtimeStatus.OutputPath, status.OutputPath)
		status.LastError = ""
		if status.OutputPath != "" {
			if info, err := os.Stat(status.OutputPath); err == nil {
				status.LastEventAt = info.ModTime()
			}
		}
		return status
	}
	status.Installed = commandExists(s.binary)
	if !status.Installed && status.Running {
		status.Installed = true
		status.Version = firstNonEmpty(status.Version, "ly-agent-adapter")
	}
	if status.OutputPath != "" {
		if info, err := os.Stat(status.OutputPath); err == nil {
			status.LastEventAt = info.ModTime()
		}
	}
	return status
}

type engineRuntimeStatusFile struct {
	Engines map[string]struct {
		Installed       bool   `json:"installed"`
		Running         bool   `json:"running"`
		Version         string `json:"version"`
		OutputPath      string `json:"output_path"`
		RulePackVersion string `json:"rule_pack_version"`
	} `json:"engines"`
}

func engineRuntimeStatusFromFile(ctx context.Context, name EngineName) (EngineStatus, bool) {
	path := firstNonEmpty(os.Getenv("ENGINE_STATUS_FILE"), "/opt/ly-engine-lab/runtime/status.json")
	if ctx.Err() != nil {
		return EngineStatus{}, false
	}
	handle, err := os.Open(path)
	if err != nil {
		return EngineStatus{}, false
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil || info.Size() > int64(agentRuntimeLimits().MemoryBytes) || info.Size() > int64(agentRuntimeLimits().ReadBytes) {
		return EngineStatus{}, false
	}
	var statusFile engineRuntimeStatusFile
	decoder := json.NewDecoder(io.LimitReader(handle, int64(agentRuntimeLimits().ReadBytes)+1))
	if err := decoder.Decode(&statusFile); err != nil {
		return EngineStatus{}, false
	}
	row, ok := statusFile.Engines[string(name)]
	if !ok {
		return EngineStatus{}, false
	}
	return EngineStatus{Name: name, Installed: row.Installed, Running: row.Running, Version: row.Version, OutputPath: row.OutputPath, RulePackVersion: row.RulePackVersion}, true
}

func commandExists(binary string) bool {
	if binary == "" {
		return false
	}
	if filepath.IsAbs(binary) {
		info, err := os.Stat(binary)
		return err == nil && !info.IsDir()
	}
	_, err := exec.LookPath(binary)
	return err == nil
}

func commandVersion(parent context.Context, binary string) string {
	if !commandExists(binary) {
		return ""
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := hiddenCommandContext(ctx, binary, "--version")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ""
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return ""
	}
	limit := int64(min(agentRuntimeLimits().ReadBytes, agentRuntimeLimits().MemoryBytes))
	out, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	if int64(len(out)) > limit {
		cancel()
	}
	waitErr := cmd.Wait()
	if readErr != nil || waitErr != nil || int64(len(out)) > limit || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

func configHash(desired EngineDesiredState) string {
	h := sha256.New()
	h.Write([]byte(desired.Name))
	h.Write([]byte(desired.Mode))
	h.Write([]byte(desired.ConfigVersion))
	h.Write([]byte(desired.RulePackVersion))
	keys := make([]string, 0, len(desired.Settings))
	for key := range desired.Settings {
		keys = append(keys, key)
	}
	sortStrings(keys)
	for _, key := range keys {
		h.Write([]byte(key))
		h.Write([]byte(desired.Settings[key]))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
