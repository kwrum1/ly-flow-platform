// Package response defines the approval and safety policy for active response
// actions. Execution adapters (Wazuh/Elkeid/firewall) live outside this package.
package response

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Risk string

const (
	RiskL1 Risk = "L1" // observe
	RiskL2 Risk = "L2" // contain
	RiskL3 Risk = "L3" // remediate
)

type Action struct {
	ID         string
	Name       string
	Risk       Risk
	Reversible bool
}

type Request struct {
	ID          string
	ActionID    string
	Target      string
	RequestedBy string
	Reason      string
	CreatedAt   time.Time
}

type Decision struct {
	RequestID        string
	Risk             Risk
	AutoApproved     bool
	ApprovalRequired bool
	ExpiresAt        time.Time
	Reason           string
}

type Policy struct {
	AllowScheduledAuto       bool
	WindowStartHour          int
	WindowEndHour            int
	RequireDifferentApprover bool
	ApprovalTTL              time.Duration
}

var (
	ErrUnknownAction  = errors.New("response: unknown action")
	ErrInvalidRequest = errors.New("response: invalid request")
	ErrFourEyes       = errors.New("response: approver must differ from requester")
)

type Engine struct {
	policy  Policy
	actions map[string]Action
}

func New(policy Policy, actions ...Action) (*Engine, error) {
	if policy.ApprovalTTL <= 0 {
		policy.ApprovalTTL = 15 * time.Minute
	}
	if policy.WindowStartHour < 0 || policy.WindowStartHour > 23 || policy.WindowEndHour < 0 || policy.WindowEndHour > 23 {
		return nil, fmt.Errorf("response: invalid window hours")
	}
	engine := &Engine{policy: policy, actions: map[string]Action{}}
	for _, action := range actions {
		if strings.TrimSpace(action.ID) == "" {
			return nil, fmt.Errorf("response: action id is required")
		}
		engine.actions[action.ID] = action
	}
	return engine, nil
}

func (engine *Engine) Evaluate(request Request, now time.Time) (Decision, error) {
	action, ok := engine.actions[request.ActionID]
	if !ok {
		return Decision{}, ErrUnknownAction
	}
	if strings.TrimSpace(request.Target) == "" || strings.TrimSpace(request.RequestedBy) == "" {
		return Decision{}, ErrInvalidRequest
	}
	decision := Decision{
		RequestID: request.ID,
		Risk:      action.Risk,
		ExpiresAt: now.Add(engine.policy.ApprovalTTL),
	}
	switch action.Risk {
	case RiskL1:
		decision.AutoApproved = true
		decision.Reason = "L1 observe action"
	case RiskL2:
		if engine.policy.AllowScheduledAuto && engine.inWindow(now) {
			decision.AutoApproved = true
			decision.Reason = "L2 action inside scheduled auto window"
		} else {
			decision.ApprovalRequired = true
			decision.Reason = "L2 action requires approval"
		}
	case RiskL3:
		decision.ApprovalRequired = true
		decision.Reason = "L3 action always requires approval"
	default:
		return Decision{}, fmt.Errorf("response: unknown risk %q", action.Risk)
	}
	return decision, nil
}

func (engine *Engine) Approve(request Request, approver string) error {
	action, ok := engine.actions[request.ActionID]
	if !ok {
		return ErrUnknownAction
	}
	if action.Risk == RiskL3 || engine.policy.RequireDifferentApprover {
		if strings.TrimSpace(approver) == "" || strings.TrimSpace(approver) == strings.TrimSpace(request.RequestedBy) {
			return ErrFourEyes
		}
	}
	return nil
}

func (engine *Engine) inWindow(now time.Time) bool {
	hour := now.UTC().Hour()
	if engine.policy.WindowStartHour <= engine.policy.WindowEndHour {
		return hour >= engine.policy.WindowStartHour && hour < engine.policy.WindowEndHour
	}
	return hour >= engine.policy.WindowStartHour || hour < engine.policy.WindowEndHour
}
