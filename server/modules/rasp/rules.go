package rasp

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

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
	ID          string    `json:"id" yaml:"id"`
	Category    string    `json:"category" yaml:"category"`
	Name        string    `json:"name" yaml:"name"`
	Severity    string    `json:"severity" yaml:"severity"`
	Languages   []string  `json:"languages,omitempty" yaml:"languages,omitempty"`
	Runtime     string    `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Description string    `json:"description" yaml:"description"`
	HookType    string    `json:"hook_type" yaml:"hook_type"`
	Patterns    []Pattern `json:"patterns" yaml:"patterns"`
	Mitre       MitreInfo `json:"mitre" yaml:"mitre"`
	Action      string    `json:"action" yaml:"action"`
	Enabled     bool      `json:"enabled" yaml:"enabled"`
}

type Pattern struct {
	Type        string `json:"type" yaml:"type"`
	Value       string `json:"value" yaml:"value"`
	Description string `json:"description" yaml:"description"`
}

type MitreInfo struct {
	Tactic    string `json:"tactic" yaml:"tactic"`
	Technique string `json:"technique" yaml:"technique"`
}

type Ruleset struct {
	Version    string       `json:"version" yaml:"version"`
	Source     string       `json:"source" yaml:"source"`
	Updated    string       `json:"updated" yaml:"updated"`
	Categories []Category   `json:"categories" yaml:"categories"`
	Rules      []ElkeidRule `json:"rules" yaml:"rules"`
}

type Category struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

func LoadElkeidRules(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Elkeid rules: %w", err)
	}
	var ruleset Ruleset
	if err := yaml.Unmarshal(data, &ruleset); err != nil {
		return nil, fmt.Errorf("decode Elkeid YAML rules: %w", err)
	}
	return &ruleset, nil
}

func ConvertToRuleset(ruleset *Ruleset) []RASPRule {
	rules := make([]RASPRule, 0, len(ruleset.Rules))
	for _, rule := range ruleset.Rules {
		if !rule.Enabled {
			continue
		}
		action := ActionBlock
		switch rule.Action {
		case "detect":
			action = ActionLog
		case "ignore":
			action = ActionIgnore
		}
		var language Language
		if len(rule.Languages) > 0 {
			switch rule.Languages[0] {
			case "java":
				language = LangJava
			case "python":
				language = LangPython
			case "nodejs":
				language = LangNodeJS
			case "php":
				language = LangPHP
			case "dotnet":
				language = LangDotNet
			}
		}
		attackType := AttackSQLInjection
		switch rule.Category {
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
		}
		pattern := ""
		for _, candidate := range rule.Patterns {
			if candidate.Type == "regex" {
				pattern = candidate.Value
				break
			}
		}
		rules = append(rules, RASPRule{
			Name: rule.Name, Language: language, AttackType: attackType, Pattern: pattern,
			Action: action, Enabled: rule.Enabled, Severity: rule.Severity, Description: rule.Description,
		})
	}
	return rules
}
