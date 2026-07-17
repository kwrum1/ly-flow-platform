package rasp

import (
	"encoding/json"
	"strings"
	"time"
)

type AttackType string

const (
	AttackSQLInjection     AttackType = "sql_injection"
	AttackXSS              AttackType = "xss"
	AttackCommandInjection AttackType = "command_injection"
	AttackPathTraversal    AttackType = "path_traversal"
	AttackSSRF             AttackType = "ssrf"
	AttackXXE              AttackType = "xxe"
	AttackDeserialization  AttackType = "deserialization"
)

type Language string

const (
	LangJava   Language = "java"
	LangPython Language = "python"
	LangNodeJS Language = "nodejs"
	LangPHP    Language = "php"
	LangDotNet Language = "dotnet"
)

type Action string

const (
	ActionBlock  Action = "block"
	ActionLog    Action = "log"
	ActionIgnore Action = "ignore"
)

type RASPEvent struct {
	ID         string                 `json:"id"`
	AgentID    string                 `json:"agent_id"`
	Hostname   string                 `json:"hostname"`
	Language   Language               `json:"language"`
	AttackType AttackType             `json:"attack_type"`
	Severity   string                 `json:"severity"`
	Action     Action                 `json:"action"`
	Blocked    bool                   `json:"blocked"`
	Request    Request                `json:"request"`
	StackTrace string                 `json:"stack_trace,omitempty"`
	User       string                 `json:"user"`
	SessionID  string                 `json:"session_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

func NormalizeEventMap(event map[string]interface{}) map[string]interface{} {
	if event == nil {
		event = map[string]interface{}{}
	}
	normalized := make(map[string]interface{}, len(event)+8)
	for key, value := range event {
		normalized[key] = value
	}
	attackType := getMapString(normalized, "attack_type")
	if attackType == "" {
		attackType = getMapString(normalized, "type")
	}
	switch attackType {
	case "sensitive_file_access":
		attackType = string(AttackPathTraversal)
	case "deserialize_injection":
		attackType = string(AttackDeserialization)
	case "":
		attackType = "unknown"
	}
	blocked, _ := normalized["blocked"].(bool)
	action := getMapString(normalized, "action")
	if action == "" {
		if blocked {
			action = string(ActionBlock)
		} else {
			action = string(ActionLog)
		}
	}
	normalized["type"] = "rasp.attack"
	normalized["attack_type"] = attackType
	if getMapString(normalized, "language") == "" {
		normalized["language"] = string(LangPython)
	}
	if getMapString(normalized, "app") == "" {
		normalized["app"] = "unknown"
	}
	if getMapString(normalized, "severity") == "" {
		normalized["severity"] = "medium"
	}
	normalized["blocked"] = blocked
	normalized["action"] = action
	if getMapString(normalized, "mode") == "" {
		if blocked {
			normalized["mode"] = "protect"
		} else {
			normalized["mode"] = "monitor"
		}
	}
	if getMapString(normalized, "rule_id") == "" {
		normalized["rule_id"] = "rasp-" + strings.ReplaceAll(attackType, "_", "-")
	}
	if getMapString(normalized, "occurred_at") == "" {
		normalized["occurred_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return normalized
}

func getMapString(values map[string]interface{}, key string) string {
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}

type Request struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	Param    map[string]string `json:"param"`
	FormData map[string]string `json:"form_data"`
	ClientIP string            `json:"client_ip"`
}

func (event *RASPEvent) ToJSON() ([]byte, error) {
	return json.Marshal(event)
}

func (event *RASPEvent) FromJSON(data []byte) error {
	return json.Unmarshal(data, event)
}

type RASPEventInput struct {
	Type       string                 `json:"type"`
	AgentID    string                 `json:"agent_id"`
	Hostname   string                 `json:"hostname"`
	Language   string                 `json:"language"`
	AttackType string                 `json:"attack_type"`
	Severity   string                 `json:"severity"`
	Action     string                 `json:"action"`
	Blocked    bool                   `json:"blocked"`
	Request    map[string]interface{} `json:"request"`
	User       string                 `json:"user"`
	SessionID  string                 `json:"session_id"`
	Timestamp  string                 `json:"timestamp"`
	StackTrace string                 `json:"stack_trace"`
}

func (input *RASPEventInput) ToRASPEvent() (*RASPEvent, error) {
	event := &RASPEvent{
		ID: "rasp-" + time.Now().Format("20060102150405"), AgentID: input.AgentID, Hostname: input.Hostname,
		Language: Language(input.Language), AttackType: AttackType(input.AttackType), Severity: input.Severity,
		Action: Action(input.Action), Blocked: input.Blocked, User: input.User, SessionID: input.SessionID, StackTrace: input.StackTrace,
	}
	if input.Timestamp != "" {
		if timestamp, err := time.Parse(time.RFC3339, input.Timestamp); err == nil {
			event.Timestamp = timestamp
		}
	}
	if input.Request != nil {
		event.Request = Request{Method: getString(input.Request, "method"), URL: getString(input.Request, "url"), ClientIP: getString(input.Request, "client_ip")}
		if parameters, ok := input.Request["param"].(map[string]interface{}); ok {
			event.Request.Param = make(map[string]string)
			for key, value := range parameters {
				if text, ok := value.(string); ok {
					event.Request.Param[key] = text
				}
			}
		}
	}
	return event, nil
}

func getString(values map[string]interface{}, key string) string {
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}

type RASPStats struct {
	TotalEvents  int64            `json:"total_events"`
	TodayEvents  int64            `json:"today_events"`
	Blocked      int64            `json:"blocked"`
	Allowed      int64            `json:"allowed"`
	ByLanguage   map[string]int64 `json:"by_language"`
	ByAttackType map[string]int64 `json:"by_attack_type"`
	Critical     int64            `json:"critical"`
	High         int64            `json:"high"`
	Medium       int64            `json:"medium"`
	Low          int64            `json:"low"`
	TopAttackers map[string]int64 `json:"top_attackers"`
	TopTargets   map[string]int64 `json:"top_targets"`
}
