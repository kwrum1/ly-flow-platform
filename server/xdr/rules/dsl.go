package rules

import (
	"fmt"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type BehaviorRulePackage struct {
	Metadata BehaviorMetadata `yaml:"metadata" json:"metadata"`
	Match    BehaviorMatch    `yaml:"match" json:"match"`
	Sequence []BehaviorStep   `yaml:"sequence" json:"sequence"`
	Entities []string         `yaml:"entities" json:"entities"`
	Score    BehaviorScore    `yaml:"score" json:"score"`
	Action   BehaviorAction   `yaml:"action" json:"action"`
	Tests    BehaviorTests    `yaml:"tests" json:"tests"`
}

type BehaviorMetadata struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Source      string   `yaml:"source" json:"source"`
	Version     string   `yaml:"version" json:"version"`
	Tags        []string `yaml:"tags" json:"tags"`
	Description string   `yaml:"description" json:"description"`
}

type BehaviorMatch struct {
	When  []BehaviorCondition `yaml:"when" json:"when"`
	Where []BehaviorCondition `yaml:"where" json:"where"`
}

type BehaviorCondition struct {
	Field    string      `yaml:"field" json:"field"`
	Operator string      `yaml:"operator" json:"operator"`
	Value    interface{} `yaml:"value" json:"value"`
}

type BehaviorStep struct {
	Name     string              `yaml:"name" json:"name"`
	Required bool                `yaml:"required" json:"required"`
	Window   string              `yaml:"window" json:"window"`
	Match    []BehaviorCondition `yaml:"match" json:"match"`
}

type BehaviorScore struct {
	BaseScore int    `yaml:"base_score" json:"base_score"`
	Severity  string `yaml:"severity" json:"severity"`
}

type BehaviorAction struct {
	Type string `yaml:"type" json:"type"`
}

type BehaviorTests struct {
	Positive []string `yaml:"positive" json:"positive"`
	Negative []string `yaml:"negative" json:"negative"`
}

func ConvertRuleToBehavior(rule models.Rule, sourceFormat string) (BehaviorRulePackage, error) {
	if rule.ID == 0 || strings.TrimSpace(rule.Name) == "" {
		return BehaviorRulePackage{}, fmt.Errorf("rule id and name are required")
	}
	operator := "contains"
	if rule.IsRegex {
		operator = "regex"
	}
	severity := severityFromLevel(rule.Level)
	return BehaviorRulePackage{
		Metadata: BehaviorMetadata{
			ID:          fmt.Sprintf("%s-%d", strings.ToLower(sourceFormat), rule.ID),
			Name:        rule.Name,
			Source:      sourceFormat,
			Version:     "v1",
			Tags:        rule.Groups,
			Description: rule.Description,
		},
		Match: BehaviorMatch{When: []BehaviorCondition{{Field: "message", Operator: operator, Value: rule.Match}}, Where: sourceConditions(rule)},
		Sequence: []BehaviorStep{{Name: "matched_behavior", Required: true, Window: fmt.Sprintf("%ds", maxInt(rule.Timeframe, 300)), Match: []BehaviorCondition{{Field: "source_module", Operator: "eq", Value: sourceModule(rule.Source)}}}},
		Entities: []string{"agent_id", "host_id", "user", "src_ip", "process"},
		Score:    BehaviorScore{BaseScore: rule.Level, Severity: severity},
		Action:   BehaviorAction{Type: actionForLevel(rule.Level)},
		Tests:    BehaviorTests{Positive: []string{fmt.Sprintf("fixtures/%s/%d-positive.json", strings.ToLower(sourceFormat), rule.ID)}, Negative: []string{fmt.Sprintf("fixtures/%s/%d-negative.json", strings.ToLower(sourceFormat), rule.ID)}},
	}, nil
}

func sourceConditions(rule models.Rule) []BehaviorCondition {
	conditions := []BehaviorCondition{{Field: "source_module", Operator: "eq", Value: sourceModule(rule.Source)}}
	if rule.SrcIP != "" {
		conditions = append(conditions, BehaviorCondition{Field: "src_ip", Operator: "eq", Value: rule.SrcIP})
	}
	if rule.User != "" {
		conditions = append(conditions, BehaviorCondition{Field: "user", Operator: "eq", Value: rule.User})
	}
	return conditions
}

func severityFromLevel(level int) string {
	switch {
	case level >= 12:
		return "critical"
	case level >= 8:
		return "high"
	case level >= 4:
		return "medium"
	default:
		return "low"
	}
}

func actionForLevel(level int) string {
	if level >= 10 {
		return "create_incident"
	}
	if level >= 6 {
		return "create_alert"
	}
	return "create_event"
}

func sourceModule(source string) string {
	s := strings.ToLower(source)
	if strings.Contains(s, "rasp") {
		return "rasp"
	}
	if strings.Contains(s, "runtime") || strings.Contains(s, "audit") || strings.Contains(s, "sshd") {
		return "runtime"
	}
	if strings.Contains(s, "dpi") || strings.Contains(s, "suricata") || strings.Contains(s, "http") {
		return "dpi"
	}
	return "xdr"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
