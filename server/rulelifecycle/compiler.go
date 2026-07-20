package rulelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type strictBundle struct {
	Version string       `json:"version"`
	Rules   []strictRule `json:"rules"`
}

type RuleCategory string

const (
	RuleCategoryTraffic  RuleCategory = "traffic"
	RuleCategoryRuntime  RuleCategory = "runtime"
	RuleCategoryRASP     RuleCategory = "rasp"
	RuleCategoryLogAudit RuleCategory = "log_audit"
	RuleCategoryArtifact RuleCategory = "artifact"
)

func parseRuleCategory(raw string) (RuleCategory, error) {
	switch RuleCategory(raw) {
	case RuleCategoryTraffic, RuleCategoryRuntime, RuleCategoryRASP, RuleCategoryLogAudit, RuleCategoryArtifact:
		return RuleCategory(raw), nil
	default:
		return "", fmt.Errorf("unsupported category %q: %w", raw, ErrCompile)
	}
}

type strictRule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Category   RuleCategory      `json:"category"`
	Severity   string            `json:"severity"`
	ScoreHint  int               `json:"score_hint,omitempty"`
	StageHint  string            `json:"stage_hint,omitempty"`
	Field      string            `json:"field,omitempty"`
	Value      string            `json:"value,omitempty"`
	Operator   string            `json:"operator,omitempty"`
	Regex      bool              `json:"regex,omitempty"`
	Conditions []strictCondition `json:"conditions,omitempty"`
	Window     *strictWindow     `json:"window,omitempty"`
	GroupBy    string            `json:"group_by,omitempty"`
	Candidate  bool              `json:"candidate"`
}

type strictCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Regex    bool   `json:"regex,omitempty"`
}

type strictWindow struct {
	Seconds   int    `json:"seconds,omitempty"`
	Count     int    `json:"count,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
	GroupBy   string `json:"group_by,omitempty"`
}

func compileStrict(content []byte, revision string) (Preview, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var bundle strictBundle
	if err := decoder.Decode(&bundle); err != nil {
		return Preview{}, fmt.Errorf("decode bundle: %w: %w", err, ErrCompile)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Preview{}, err
	}
	if bundle.Version != revision || len(bundle.Rules) == 0 {
		return Preview{}, fmt.Errorf("bundle revision or rules invalid: %w", ErrCompile)
	}
	seen := make(map[string]struct{}, len(bundle.Rules))
	for index, rule := range bundle.Rules {
		if err := validateRule(rule, seen); err != nil {
			return Preview{}, fmt.Errorf("rule %d: %w", index, err)
		}
		seen[rule.ID] = struct{}{}
	}
	return Preview{Revision: revision, RuleCount: len(bundle.Rules), WouldActivate: false}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing bundle content: %w", ErrCompile)
	}
	return nil
}

func validateRule(rule strictRule, seen map[string]struct{}) error {
	if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("missing identity: %w", ErrCompile)
	}
	if _, exists := seen[rule.ID]; exists {
		return fmt.Errorf("duplicate id %s: %w", rule.ID, ErrCompile)
	}
	if _, err := parseRuleCategory(string(rule.Category)); err != nil {
		return err
	}
	if !containsExact([]string{"critical", "high", "medium", "low", "info"}, rule.Severity) {
		return fmt.Errorf("unsupported category or severity: %w", ErrCompile)
	}
	if rule.ScoreHint < 0 || rule.ScoreHint > 100 {
		return fmt.Errorf("score outside 0..100: %w", ErrCompile)
	}
	if len(rule.Conditions) == 0 {
		return validateCondition(strictCondition{Field: rule.Field, Operator: rule.Operator, Value: rule.Value, Regex: rule.Regex})
	}
	for _, condition := range rule.Conditions {
		if err := validateCondition(condition); err != nil {
			return err
		}
	}
	return nil
}

func validateCondition(condition strictCondition) error {
	operator := strings.ToLower(strings.TrimSpace(condition.Operator))
	if operator == "" {
		if condition.Regex {
			operator = "regex"
		} else {
			operator = "contains"
		}
	}
	if strings.TrimSpace(condition.Field) == "" || !containsExact([]string{"contains", "regex", "equals", "eq", "prefix", "suffix", "exists", "not_equals", "neq", "not_exists"}, operator) {
		return fmt.Errorf("unsupported condition: %w", ErrCompile)
	}
	if operator != "exists" && operator != "not_exists" && strings.TrimSpace(condition.Value) == "" {
		return fmt.Errorf("condition value required: %w", ErrCompile)
	}
	if operator == "regex" || condition.Regex {
		if _, err := regexp.Compile(condition.Value); err != nil {
			return fmt.Errorf("invalid regular expression: %w", ErrCompile)
		}
	}
	return nil
}

func containsExact(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
