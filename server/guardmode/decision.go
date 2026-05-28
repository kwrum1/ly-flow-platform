package guardmode

import (
	"encoding/json"
	"fmt"
)

type Decision struct {
	Action     string  `json:"action"`
	Confidence float64 `json:"confidence"`
	TargetIP   string  `json:"target_ip"`
	Reason     string  `json:"reason"`
}

type SafetyContext struct {
	Severity        string
	RuleHit         bool
	MultiSignal     bool
	WhitelistPassed bool
	AllowedWindow   bool
}

func ParseDecision(payload []byte) (Decision, error) {
	var decision Decision
	if err := json.Unmarshal(payload, &decision); err != nil {
		return Decision{}, err
	}
	if decision.Action == "" || decision.Confidence < 0 || decision.Confidence > 1 {
		return Decision{}, fmt.Errorf("invalid decision")
	}
	return decision, nil
}

func Allowed(decision Decision, ctx SafetyContext, threshold float64) bool {
	if decision.Action != "temporary_block" && decision.Action != "notify_only" {
		return false
	}
	if decision.Confidence < threshold || !ctx.AllowedWindow || !ctx.RuleHit || !ctx.MultiSignal || !ctx.WhitelistPassed {
		return false
	}
	return ctx.Severity == "critical" || ctx.Severity == "high"
}
