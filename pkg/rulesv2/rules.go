package rulesv2

import "github.com/lyflow/ly-flow-platform/contracts"

const SchemaVersion = "lyflow.rule.v2"

type SupportLevel string

const (
	SupportFull        SupportLevel = "full_supported"
	SupportPartial     SupportLevel = "partial_supported"
	SupportUnsupported SupportLevel = "unsupported"
)

type RuleEnvelope struct {
	SchemaVersion   string                      `json:"schema_version"`
	ID              string                      `json:"id"`
	Name            string                      `json:"name"`
	Description     string                      `json:"description,omitempty"`
	Category        contracts.TelemetryCategory `json:"category"`
	Enabled         bool                        `json:"enabled"`
	Source          RuleSource                  `json:"source"`
	Support         RuleSupport                 `json:"support"`
	Classification  RuleClassification          `json:"classification"`
	Scoring         RuleScoring                 `json:"scoring"`
	DPI             *DpiRuleSpec                `json:"dpi,omitempty"`
	Runtime         *RuntimeRuleSpec            `json:"runtime,omitempty"`
	RASP            *RaspRuleSpec               `json:"rasp,omitempty"`
	LogAudit        *LogAuditRuleSpec           `json:"log_audit,omitempty"`
	Provenance      []RuleProvenance            `json:"provenance,omitempty"`
	Response        RuleResponse                `json:"response,omitempty"`
	DedupKey        string                      `json:"dedup_key,omitempty"`
	ExecutionTarget string                      `json:"execution_target,omitempty"`
	HotReloadable   bool                        `json:"hot_reloadable"`
}

type RuleSource struct {
	Origin     string `json:"origin"`
	Vendor     string `json:"vendor,omitempty"`
	License    string `json:"license,omitempty"`
	URL        string `json:"url,omitempty"`
	Version    string `json:"version,omitempty"`
	UpstreamID string `json:"upstream_id,omitempty"`
	Revision   string `json:"revision,omitempty"`
	Connector  bool   `json:"connector,omitempty"`
	Bundled    bool   `json:"bundled,omitempty"`
}

type RuleSupport struct {
	Level             SupportLevel `json:"level"`
	UnsupportedFields []string     `json:"unsupported_fields,omitempty"`
	Notes             []string     `json:"notes,omitempty"`
	LossOfSemantics   []string     `json:"loss_of_semantics,omitempty"`
}

type RuleClassification struct {
	Stage           string   `json:"stage,omitempty"`
	MitreTactics    []string `json:"mitre_tactics,omitempty"`
	MitreTechniques []string `json:"mitre_techniques,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
	Rationale       string   `json:"rationale,omitempty"`
}

type RuleScoring struct {
	BaseScore         int    `json:"base_score"`
	Severity          string `json:"severity"`
	SourceReliability int    `json:"source_reliability,omitempty"`
}

type MatchCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Regex    bool   `json:"regex,omitempty"`
	CaseFold bool   `json:"case_fold,omitempty"`
}

type DpiRuleSpec struct {
	Protocol   string           `json:"protocol,omitempty"`
	Conditions []MatchCondition `json:"conditions"`
	Window     *WindowSpec      `json:"window,omitempty"`
}

type RuntimeRuleSpec struct {
	EventTypes []string         `json:"event_types,omitempty"`
	Conditions []MatchCondition `json:"conditions"`
	Window     *WindowSpec      `json:"window,omitempty"`
}

type RaspRuleSpec struct {
	Languages  []string         `json:"languages,omitempty"`
	HookTypes  []string         `json:"hook_types,omitempty"`
	Conditions []MatchCondition `json:"conditions"`
	Action     string           `json:"action,omitempty"`
}

type LogAuditRuleSpec struct {
	Sources    []string         `json:"sources,omitempty"`
	Parser     string           `json:"parser,omitempty"`
	Conditions []MatchCondition `json:"conditions"`
	Extract    []string         `json:"extract,omitempty"`
	Window     *WindowSpec      `json:"window,omitempty"`
}

type WindowSpec struct {
	Seconds int    `json:"seconds"`
	Count   int    `json:"count"`
	GroupBy string `json:"group_by,omitempty"`
}

type RuleProvenance struct {
	Source string `json:"source"`
	Ref    string `json:"ref,omitempty"`
	Raw    string `json:"raw,omitempty"`
}

type RuleResponse struct {
	CandidateOnly         bool     `json:"candidate_only"`
	AllowedCandidateTypes []string `json:"allowed_candidate_types,omitempty"`
}

func (r RuleEnvelope) Validate() error {
	if r.SchemaVersion != SchemaVersion || r.ID == "" || r.Name == "" || r.Category == "" || r.Support.Level == "" {
		return ValidationError("missing required rule field")
	}
	if r.Scoring.BaseScore < 0 || r.Scoring.BaseScore > 100 {
		return ValidationError("base_score out of range")
	}
	if r.Support.Level == SupportUnsupported && r.Enabled {
		return ValidationError("unsupported rule cannot be enabled")
	}
	specs := 0
	if r.DPI != nil {
		specs++
	}
	if r.Runtime != nil {
		specs++
	}
	if r.RASP != nil {
		specs++
	}
	if r.LogAudit != nil {
		specs++
	}
	if specs != 1 {
		return ValidationError("exactly one category spec is required")
	}
	if r.Category == contracts.TelemetryTraffic && r.DPI == nil {
		return ValidationError("dpi spec required")
	}
	if r.Category == contracts.TelemetryRuntime && r.Runtime == nil {
		return ValidationError("runtime spec required")
	}
	if r.Category == contracts.TelemetryRASP && r.RASP == nil {
		return ValidationError("rasp spec required")
	}
	if r.Category == contracts.TelemetryLogAudit && r.LogAudit == nil {
		return ValidationError("log_audit spec required")
	}
	return nil
}

type ValidationError string

func (e ValidationError) Error() string { return string(e) }
