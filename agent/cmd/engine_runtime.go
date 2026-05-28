package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

func (a *Agent) runEngineAdapters() {
	if a.engines != nil {
		a.engines.Apply(a.ctx, defaultEngineDesiredStatesFromConfig(a.cfg))
	}
	go a.runSuricataEVEAdapter()
	if a.cfg.HIDSEnabled {
		go a.runWazuhAlertAdapter()
		go a.runYARAArtifactAdapter()
	}
	if a.cfg.RASPEnabled {
		go a.runRASPEventAdapter()
	}
}

func (a *Agent) runSuricataEVEAdapter() {
	path := a.suricataEVEPath()
	if path == "" {
		return
	}
	var offset int64
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		next, err := a.consumeSuricataEVEFile(path, offset)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("[suricata] eve adapter warning: %v\n", err)
		}
		if next >= 0 {
			offset = next
		}
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) consumeSuricataEVEFile(path string, offset int64) (int64, error) {
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
	reader := bufio.NewReader(f)
	current := offset
	for {
		line, err := reader.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			raw := contracts.RawReference{Path: path, Offset: current, SourceEngine: contracts.SourceEngineSuricata}
			alert, ok, parseErr := componentAlertFromSuricataEVE(line, a, raw)
			if parseErr != nil {
				fmt.Printf("[suricata] eve parse warning offset=%d err=%v\n", current, parseErr)
			} else if ok {
				if err := a.publishComponentAlert(alert); err != nil {
					fmt.Printf("[suricata] component alert publish failed: %v\n", err)
				}
			}
		}
		current += int64(len(line))
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		return current, err
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
	body, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	_, err = httpPost(a.cfg.API+"/api/v1/agent/component-alert", body)
	return err
}

func (a *Agent) suricataEVEPath() string {
	if a.engines != nil {
		if status, ok := a.engines.Snapshot(context.Background())[EngineSuricata]; ok && status.OutputPath != "" {
			return status.OutputPath
		}
	}
	return "/var/log/suricata/eve.json"
}

func (a *Agent) runWazuhAlertAdapter() {
	a.runJSONLineAdapter(EngineWazuh, a.wazuhAlertPath(), func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
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
	a.runJSONLineAdapter(EngineYARA, a.yaraResultPath(), func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
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
	a.runJSONLineAdapter(EngineRASP, a.raspEventPath(), func(values map[string]interface{}, raw contracts.RawReference) (contracts.ComponentAlert, bool, error) {
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
	if path == "" {
		return
	}
	var offset int64
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}
		next, err := a.consumeJSONLineAlertFile(engine, path, offset, convert)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Printf("[%s] adapter warning: %v\n", engine, err)
		}
		if next >= 0 {
			offset = next
		}
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) consumeJSONLineAlertFile(engine EngineName, path string, offset int64, convert func(map[string]interface{}, contracts.RawReference) (contracts.ComponentAlert, bool, error)) (int64, error) {
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
	reader := bufio.NewReader(f)
	current := offset
	for {
		line, err := reader.ReadBytes('\n')
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
		current += int64(len(line))
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		return current, err
	}
	return current, nil
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
		{Name: EngineSuricata, Enabled: cfg == nil || cfg.TrafficEnabled, Mode: "suricata_live", RulePackVersion: "et-open-active", Settings: map[string]string{"output_path": "/var/log/suricata/eve.json"}},
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
