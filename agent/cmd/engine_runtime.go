package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func (a *Agent) runEngineAdapters() {
	if a.engines != nil {
		a.engines.Apply(a.ctx, defaultEngineDesiredStatesFromConfig(a.cfg))
	}
	if suricataProfileEnabled() {
		health := newRuntimeControlHealth("agent-suricata-adapter", agentRuntimeLimits(), time.Now)
		go runSupervisedRuntime(a.ctx, health, runtimeSupervisorConfig{
			Name: "suricata", Run: func(ctx context.Context) { a.runSuricataEVEAdapterContext(withRuntimeHealth(ctx, health)) }, OnHealth: a.handleControlHealth,
		})
	}
	if a.cfg.HIDSEnabled {
		wazuhHealth := newRuntimeControlHealth("agent-wazuh-adapter", agentRuntimeLimits(), time.Now)
		go runSupervisedRuntime(a.ctx, wazuhHealth, runtimeSupervisorConfig{
			Name: "wazuh", Run: func(ctx context.Context) { a.runWazuhAlertAdapterContext(withRuntimeHealth(ctx, wazuhHealth)) }, OnHealth: a.handleControlHealth,
		})
		yaraHealth := newRuntimeControlHealth("agent-yara-adapter", agentRuntimeLimits(), time.Now)
		go runSupervisedRuntime(a.ctx, yaraHealth, runtimeSupervisorConfig{
			Name: "yara", Run: func(ctx context.Context) { a.runYARAArtifactAdapterContext(withRuntimeHealth(ctx, yaraHealth)) }, OnHealth: a.handleControlHealth,
		})
	}
}

func (a *Agent) runSuricataEVEAdapter() {
	a.runSuricataEVEAdapterContext(a.ctx)
}

func (a *Agent) runSuricataEVEAdapterContext(ctx context.Context) {
	path := a.suricataEVEPath()
	if path == "" {
		return
	}
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		next, err := a.consumeSuricataEVEFileContext(ctx, path, offset)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("[suricata] eve adapter warning: %v\n", err)
		}
		if isRuntimeBudgetError(err) {
			return
		}
		if next >= 0 {
			offset = next
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) consumeSuricataEVEFile(path string, offset int64) (int64, error) {
	return a.consumeSuricataEVEFileContext(a.ctx, path, offset)
}

func (a *Agent) consumeSuricataEVEFileContext(ctx context.Context, path string, offset int64) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return offset, err
	}
	if offset > info.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	current := offset
	budget := newRuntimeBudget(agentRuntimeLimits(), time.Now)
	for {
		health := a.runtimeHealthFor(ctx)
		health.TouchWatchdog()
		if !budget.Allow(ctx, 0) {
			health.Degrade("cpu_or_read_budget_exceeded", false)
			return current, errRuntimeCPUBudget
		}
		line, err := readBoundedSuricataLine(reader)
		if err != nil {
			return current, err
		}
		if line.bytesRead == 0 {
			break
		}
		if line.oversized {
			health.Degrade("read_or_memory_budget_exceeded", false)
			atomic.AddUint64(&a.suricataProfile.oversizedLines, 1)
			a.deadLetterSuricata(path, current, line, "line_too_large")
			current += line.bytesRead
			continue
		}
		if !budget.Allow(ctx, int(line.bytesRead)) {
			health.Degrade("cpu_or_read_budget_exceeded", false)
			if budget.read > agentRuntimeLimits().ReadBytes {
				return current, errRuntimeReadLimit
			}
			return current, errRuntimeCPUBudget
		}
		if !line.complete {
			atomic.AddUint64(&a.suricataProfile.truncatedLines, 1)
			if a.suricataProfile.observePartial(current, line.bytesRead) {
				return current, nil
			}
			a.deadLetterSuricata(path, current, line, "truncated_line")
			current += line.bytesRead
			break
		}
		a.suricataProfile.clearPartial()
		trimmed := bytes.TrimSpace(line.data)
		if len(trimmed) > 0 {
			context := newSuricataProfileContext(a.agentID, a.hostname).withRaw(contracts.RawReference{Path: path, Offset: current})
			record, parseErr := parseSuricataProfileLine(trimmed, context)
			if parseErr != nil {
				reason := a.noteSuricataParseError(parseErr)
				a.deadLetterSuricata(path, current, line, reason)
				fmt.Printf("[suricata] eve parse warning offset=%d err=%v\n", current, parseErr)
			} else {
				atomic.AddUint64(&a.suricataProfile.parsedLines, 1)
				atomic.StoreInt64(&a.suricataProfile.lastEventUnix, record.eventTime().Unix())
				if err := a.publishSuricataRecord(record); err != nil {
					atomic.AddUint64(&a.suricataProfile.publishErrors, 1)
					a.suricataProfile.lastError.Store(err.Error())
					fmt.Printf("[suricata] profile record publish failed: %v\n", err)
				}
			}
		}
		current += line.bytesRead
	}
	return current, nil
}

func (a *Agent) publishComponentAlert(alert contracts.ComponentAlert) error {
	if a.agentID != "" && alert.Entities.AgentID == "" {
		alert.Entities.AgentID = a.agentID
	}
	if a.hostname != "" && alert.Entities.Hostname == "" {
		alert.Entities.Hostname = a.hostname
	}
	return a.publishAgentStream(a.ctx, "component_alerts:v2", structToMap(alert), "component_alert")
}

func (a *Agent) suricataEVEPath() string {
	if suricataProfileEnabled() {
		if path := strings.TrimSpace(os.Getenv("SURICATA_EVE")); path != "" {
			return path
		}
	}
	if a.engines != nil {
		if status, ok := a.engines.Snapshot(context.Background())[EngineSuricata]; ok && status.OutputPath != "" {
			return status.OutputPath
		}
	}
	return "/var/log/suricata/eve.json"
}

func (a *Agent) runWazuhAlertAdapter() {
	a.runWazuhAlertAdapterContext(a.ctx)
}

func (a *Agent) runWazuhAlertAdapterContext(ctx context.Context) {
	a.runJSONLineAdapterContext(ctx, EngineWazuh, a.wazuhAlertPath(), func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		input := wazuhAlertInput{
			RuleID:    firstNonEmpty(jsonString(values, "rule.id"), jsonString(values, "rule_id"), jsonString(values, "id")),
			RuleName:  firstNonEmpty(jsonString(values, "rule.description"), jsonString(values, "description"), jsonString(values, "rule_name")),
			Level:     jsonInt(values, "rule.level", "level"),
			Decoder:   firstNonEmpty(jsonString(values, "decoder.name"), jsonString(values, "decoder")),
			Location:  jsonString(values, "location"),
			FullLog:   firstNonEmpty(jsonString(values, "full_log"), jsonString(values, "message")),
			Timestamp: jsonTime(values, "timestamp", "occurred_at"),
		}
		if input.RuleID == "" && input.FullLog == "" {
			return contracts.ComponentAlert{}, false, nil
		}
		alert, err := componentAlertFromWazuh(input, a, raw)
		return alert, err == nil, err
	})
}

func (a *Agent) runYARAArtifactAdapter() {
	a.runYARAArtifactAdapterContext(a.ctx)
}

func (a *Agent) runYARAArtifactAdapterContext(ctx context.Context) {
	a.runJSONLineAdapterContext(ctx, EngineYARA, a.yaraResultPath(), func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		input := yaraMatchInput{
			Rule:      firstNonEmpty(jsonString(values, "rule"), jsonString(values, "rule_id"), jsonString(values, "name")),
			Namespace: jsonString(values, "namespace"),
			Tags:      jsonStringSlice(values["tags"]),
			FilePath:  firstNonEmpty(jsonString(values, "file_path"), jsonString(values, "path")),
			FileHash:  firstNonEmpty(jsonString(values, "file_hash"), jsonString(values, "sha256"), jsonString(values, "md5")),
			MatchedAt: jsonTime(values, "matched_at", "timestamp", "occurred_at"),
		}
		if input.Rule == "" || input.FilePath == "" {
			return contracts.ComponentAlert{}, false, nil
		}
		alert, err := componentAlertFromYARA(input, a, raw)
		return alert, err == nil, err
	})
}

func (a *Agent) runRASPEventAdapter() {
	a.runRASPEventAdapterContext(a.ctx)
}

func (a *Agent) runRASPEventAdapterContext(ctx context.Context) {
	a.runJSONLineAdapterContext(ctx, EngineRASP, a.raspEventPath(), func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
		now := time.Now().UTC()
		a.enforceRASPPolicyExpiry(now)
		if !a.raspPolicyEnabled() || !a.allowRASPEvent(now) {
			return contracts.ComponentAlert{}, false, nil
		}
		input := raspEventInput{
			RuleID:      firstNonEmpty(jsonString(values, "rule_id"), jsonString(values, "rule.id"), jsonString(values, "id")),
			RuleName:    firstNonEmpty(jsonString(values, "rule_name"), jsonString(values, "rule.name"), jsonString(values, "name")),
			HookType:    firstNonEmpty(jsonString(values, "hook_type"), jsonString(values, "hook"), jsonString(values, "type")),
			Language:    jsonString(values, "language"),
			Runtime:     jsonString(values, "runtime"),
			Application: firstNonEmpty(jsonString(values, "application"), jsonString(values, "app"), jsonString(values, "service")),
			Action:      firstNonEmpty(jsonString(values, "action"), string(contracts.ActionAudit)),
			Evidence:    firstNonEmpty(jsonString(values, "evidence"), jsonString(values, "message"), jsonString(values, "summary")),
			OccurredAt:  jsonTime(values, "occurred_at", "timestamp", "time"),
		}
		if input.RuleID == "" && input.Evidence == "" {
			return contracts.ComponentAlert{}, false, nil
		}
		alert, err := componentAlertFromRASP(input, a, raw)
		return alert, err == nil, err
	})
}

func (a *Agent) runJSONLineAdapter(engine EngineName, path string, convert func(map[string]interface{}, contracts.RawReference) (contracts.ComponentAlert, bool, error)) {
	a.runJSONLineAdapterContext(a.ctx, engine, path, convert)
}

func (a *Agent) runJSONLineAdapterContext(ctx context.Context, engine EngineName, path string, convert func(map[string]interface{}, contracts.RawReference) (contracts.ComponentAlert, bool, error)) {
	if path == "" {
		return
	}
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		next, err := a.consumeJSONLineAlertFileContext(ctx, engine, path, offset, convert)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("[%s] adapter warning: %v\n", engine, err)
		}
		if isRuntimeBudgetError(err) {
			return
		}
		if next >= 0 {
			offset = next
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) consumeJSONLineAlertFile(engine EngineName, path string, offset int64, convert func(map[string]interface{}, contracts.RawReference) (contracts.ComponentAlert, bool, error)) (int64, error) {
	return a.consumeJSONLineAlertFileContext(a.ctx, engine, path, offset, convert)
}

func (a *Agent) consumeJSONLineAlertFileContext(ctx context.Context, engine EngineName, path string, offset int64, convert func(map[string]interface{}, contracts.RawReference) (contracts.ComponentAlert, bool, error)) (int64, error) {
	health := a.runtimeHealthFor(ctx)
	health.TouchWatchdog()
	f, err := os.Open(path)
	if err != nil {
		return offset, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return offset, err
	}
	if offset > info.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	current := offset
	budget := newRuntimeBudget(agentRuntimeLimits(), time.Now)
	for {
		health.TouchWatchdog()
		bounded, err := readBoundedSuricataLine(reader)
		line := bounded.data
		if bounded.oversized || int(bounded.bytesRead) > agentRuntimeLimits().MemoryBytes {
			health.Degrade("read_or_memory_budget_exceeded", false)
			return current, errRuntimeReadLimit
		}
		if !budget.Allow(ctx, int(bounded.bytesRead)) {
			health.Degrade("cpu_or_read_budget_exceeded", false)
			if budget.read > agentRuntimeLimits().ReadBytes {
				return current, errRuntimeReadLimit
			}
			return current, errRuntimeCPUBudget
		}
		if len(strings.TrimSpace(string(line))) > 0 {
			var values map[string]interface{}
			if parseErr := json.Unmarshal(line, &values); parseErr == nil {
				raw := contracts.RawReference{Path: path, Offset: current, SourceEngine: contracts.SourceEngine(engine), EventType: "alert"}
				alert, ok, convertErr := convert(values, raw)
				if convertErr != nil {
					fmt.Printf("[%s] convert warning offset=%d err=%v\n", engine, current, convertErr)
				} else if ok {
					if err := a.publishComponentAlert(alert); err != nil {
						fmt.Printf("[%s] component alert publish failed: %v\n", engine, err)
					}
				}
			}
		}
		current += bounded.bytesRead
		if err != nil {
			return current, err
		}
		if !bounded.complete {
			break
		}
	}
	return current, nil
}

func isRuntimeBudgetError(err error) bool {
	return errors.Is(err, errRuntimeReadLimit) || errors.Is(err, errRuntimeCPUBudget) || errors.Is(err, errRuntimeMemoryLimit)
}

func (a *Agent) wazuhAlertPath() string {
	return a.engineOutputPath(EngineWazuh, "/var/ossec/logs/alerts/alerts.json")
}
func (a *Agent) yaraResultPath() string {
	return a.engineOutputPath(EngineYARA, "/opt/ly-agent/yara/last-scan.json")
}
func (a *Agent) raspEventPath() string {
	return a.engineOutputPath(EngineRASP, "/opt/ly-agent/rasp/events.jsonl")
}

func (a *Agent) engineOutputPath(engine EngineName, fallback string) string {
	if a.engines != nil {
		if status, ok := a.engines.Snapshot(context.Background())[engine]; ok && status.OutputPath != "" {
			return status.OutputPath
		}
	}
	return fallback
}

func defaultEngineDesiredStatesFromConfig(cfg *Config) []EngineDesiredState {
	return []EngineDesiredState{
		{Name: EngineSuricata, Enabled: suricataProfileEnabled(), Mode: "suricata_eve_profile", ConfigVersion: suricataProfileNativeSchema, RulePackVersion: suricataProfileRulePack, Settings: map[string]string{"output_path": "/var/log/suricata/eve.json", "engine_version": suricataProfileVersion}},
		{Name: EngineWazuh, Enabled: cfg == nil || cfg.HIDSEnabled, Mode: "headless-agent", RulePackVersion: "wazuh-default", Settings: map[string]string{"output_path": "/var/ossec/logs/alerts/alerts.json"}},
		{Name: EngineYARA, Enabled: cfg == nil || cfg.HIDSEnabled, Mode: "artifact-scan", RulePackVersion: "yara-security", Settings: map[string]string{"output_path": "/opt/ly-agent/yara/last-scan.json"}},
		{Name: EngineRASP, Enabled: cfg != nil && cfg.RASPEnabled, Mode: "audit-only", RulePackVersion: "rasp-active", Settings: map[string]string{"output_path": "/opt/ly-agent/rasp/events.jsonl"}},
	}
}

func jsonString(values map[string]interface{}, key string) string {
	v, ok := nestedJSONValue(values, key)
	if !ok || v == nil {
		return ""
	}
	switch typed := v.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func jsonInt(values map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if raw := jsonString(values, key); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				return n
			}
		}
	}
	return 0
}

func jsonTime(values map[string]interface{}, keys ...string) time.Time {
	for _, key := range keys {
		raw := jsonString(values, key)
		if raw == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000000-0700", "2006-01-02 15:04:05"} {
			if parsed, err := time.Parse(layout, raw); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

func nestedJSONValue(values map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := values[key]; ok {
		return v, true
	}
	var current interface{} = values
	for _, part := range strings.Split(key, ".") {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func jsonStringSlice(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if typed == "" {
			return nil
		}
		return strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ' ' })
	default:
		return nil
	}
}
