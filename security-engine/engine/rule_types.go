package engine

import (
	"regexp"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type RuntimeRule struct {
	ID         string                      `json:"id"`
	Name       string                      `json:"name"`
	Category   contracts.TelemetryCategory `json:"category"`
	Severity   contracts.AlertSeverity     `json:"severity"`
	ScoreHint  int                         `json:"score_hint"`
	StageHint  string                      `json:"stage_hint,omitempty"`
	Field      string                      `json:"field,omitempty"`
	Value      string                      `json:"value,omitempty"`
	Operator   string                      `json:"operator,omitempty"`
	Regex      bool                        `json:"regex,omitempty"`
	Conditions []MatchCondition            `json:"conditions,omitempty"`
	Window     *WindowSpec                 `json:"window,omitempty"`
	GroupBy    string                      `json:"group_by,omitempty"`
	Candidate  bool                        `json:"candidate"`
	compiled   *regexp.Regexp
}

type MatchCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value,omitempty"`
	Regex    bool   `json:"regex,omitempty"`
	compiled *regexp.Regexp
}

type WindowSpec struct {
	Seconds   int    `json:"seconds,omitempty"`
	Count     int    `json:"count,omitempty"`
	Threshold int    `json:"threshold,omitempty"`
	GroupBy   string `json:"group_by,omitempty"`
}
