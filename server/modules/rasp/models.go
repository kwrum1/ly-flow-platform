package rasp

import (
	"encoding/json"
	"os"
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

func getMapString(m map[string]interface{}, key string) string {
	if value, ok := m[key].(string); ok {
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

func (e *RASPEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

func (e *RASPEvent) FromJSON(data []byte) error {
	return json.Unmarshal(data, e)
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

func (i *RASPEventInput) ToRASPEvent() (*RASPEvent, error) {
	event := &RASPEvent{
		ID:         "rasp-" + time.Now().Format("20060102150405"),
		AgentID:    i.AgentID,
		Hostname:   i.Hostname,
		Language:   Language(i.Language),
		AttackType: AttackType(i.AttackType),
		Severity:   i.Severity,
		Action:     Action(i.Action),
		Blocked:    i.Blocked,
		User:       i.User,
		SessionID:  i.SessionID,
		StackTrace: i.StackTrace,
	}

	if i.Timestamp != "" {
		if ts, err := time.Parse(time.RFC3339, i.Timestamp); err == nil {
			event.Timestamp = ts
		}
	}

	if i.Request != nil {
		event.Request = Request{
			Method:   getString(i.Request, "method"),
			URL:      getString(i.Request, "url"),
			ClientIP: getString(i.Request, "client_ip"),
		}

		if params, ok := i.Request["param"].(map[string]interface{}); ok {
			event.Request.Param = make(map[string]string)
			for k, v := range params {
				if s, ok := v.(string); ok {
					event.Request.Param[k] = s
				}
			}
		}
	}

	return event, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
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

type RASPRule struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Language    Language   `json:"language"`
	AttackType  AttackType `json:"attack_type"`
	Pattern     string     `json:"pattern"`
	Action      Action     `json:"action"`
	Enabled     bool       `json:"enabled"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
}

type RASPConfig struct {
	AgentID   string   `json:"agent_id"`
	Language  Language `json:"language"`
	Rules     []int    `json:"rules"`
	BlockMode bool     `json:"block_mode"`
	LogLevel  string   `json:"log_level"`
}

type ElkeidRule struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Languages   []string  `json:"languages,omitempty"`
	Runtime     string    `json:"runtime,omitempty"`
	Description string    `json:"description"`
	HookType    string    `json:"hook_type"`
	Patterns    []Pattern `json:"patterns"`
	Mitre       MitreInfo `json:"mitre"`
	Action      string    `json:"action"`
	Enabled     bool      `json:"enabled"`
}

type Pattern struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

type MitreInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
}

type Ruleset struct {
	Version    string       `json:"version"`
	Source     string       `json:"source"`
	Updated    string       `json:"updated"`
	Categories []Category   `json:"categories"`
	Rules      []ElkeidRule `json:"rules"`
}

type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func LoadElkeidRules(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ruleset Ruleset
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return nil, err
	}

	return &ruleset, nil
}

func ConvertToRuleset(rs *Ruleset) []RASPRule {
	var rules []RASPRule
	for _, r := range rs.Rules {
		if !r.Enabled {
			continue
		}

		action := ActionBlock
		if r.Action == "detect" {
			action = ActionLog
		} else if r.Action == "ignore" {
			action = ActionIgnore
		}

		var lang Language
		if len(r.Languages) > 0 {
			switch r.Languages[0] {
			case "java":
				lang = LangJava
			case "python":
				lang = LangPython
			case "nodejs":
				lang = LangNodeJS
			case "php":
				lang = LangPHP
			case "dotnet":
				lang = LangDotNet
			}
		}

		var attackType AttackType
		switch r.Category {
		case "injection", "command_exec":
			attackType = AttackCommandInjection
		case "xss":
			attackType = AttackXSS
		case "file_ops", "path_traversal":
			attackType = AttackPathTraversal
		case "ssrf":
			attackType = AttackSSRF
		case "xxe":
			attackType = AttackXXE
		case "deserialization":
			attackType = AttackDeserialization
		default:
			attackType = AttackSQLInjection
		}

		var pattern string
		for _, p := range r.Patterns {
			if p.Type == "regex" {
				pattern = p.Value
				break
			}
		}

		rules = append(rules, RASPRule{
			Name:        r.Name,
			Language:    lang,
			AttackType:  attackType,
			Pattern:     pattern,
			Action:      action,
			Enabled:     r.Enabled,
			Severity:    r.Severity,
			Description: r.Description,
		})
	}
	return rules
}
