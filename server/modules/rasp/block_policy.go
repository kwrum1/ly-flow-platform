package rasp

import (
	"strings"
	"time"
)

// Block policy modes. Enforcement is off unless a signed policy explicitly
// says otherwise; dry-run reports what would have happened without touching
// the request.
const (
	BlockModeMonitor = "monitor"
	BlockModeDryRun  = "dry_run"
	BlockModeEnforce = "enforce"
)

// BlockPolicy is the fail-safe gate in front of every block decision.
// Any uncertainty (unsigned, expired, emergency stop, unknown mode) resolves
// to "allow", so a broken policy can never take production traffic down.
type BlockPolicy struct {
	Mode            string    `json:"mode"`
	PolicySigned    bool      `json:"policy_signed"`
	PolicyExpiresAt time.Time `json:"policy_expires_at,omitempty"`
	EmergencyStop   bool      `json:"emergency_stop"`
}

// BlockDecision is the auditable outcome of one policy evaluation.
type BlockDecision struct {
	Block         bool   `json:"block"`
	WouldBlock    bool   `json:"would_block"`
	Mode          string `json:"mode"`
	Reason        string `json:"reason"`
	FailSafe      bool   `json:"fail_safe"`
	EmergencyStop bool   `json:"emergency_stop"`
	PolicySigned  bool   `json:"policy_signed"`
}

func normalizeBlockMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case BlockModeEnforce:
		return BlockModeEnforce
	case BlockModeDryRun, "dry-run", "dryrun":
		return BlockModeDryRun
	default:
		return BlockModeMonitor
	}
}

// Decide reports whether a request should be blocked. Fail-safe means the
// decision defaulted to allow because the policy was not fully usable.
func (policy BlockPolicy) Decide(now time.Time, agentEnabled bool) BlockDecision {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	decision := BlockDecision{
		Mode:          normalizeBlockMode(policy.Mode),
		EmergencyStop: policy.EmergencyStop,
		PolicySigned:  policy.PolicySigned,
	}
	if decision.EmergencyStop {
		decision.Reason = "emergency_stop"
		decision.FailSafe = true
		return decision
	}
	if !agentEnabled {
		decision.Reason = "agent_not_protected"
		decision.FailSafe = true
		return decision
	}
	switch decision.Mode {
	case BlockModeMonitor:
		decision.Reason = "mode_monitor"
		return decision
	case BlockModeDryRun:
		decision.WouldBlock = policy.PolicySigned && policyUnexpired(policy.PolicyExpiresAt, now)
		if decision.WouldBlock {
			decision.Reason = "dry_run_would_block"
		} else {
			decision.Reason = "dry_run_policy_unusable"
			decision.FailSafe = true
		}
		return decision
	}

	if !policy.PolicySigned {
		decision.Reason = "unsigned_policy"
		decision.FailSafe = true
		return decision
	}
	if !policyUnexpired(policy.PolicyExpiresAt, now) {
		decision.Reason = "policy_expired"
		decision.FailSafe = true
		return decision
	}
	decision.Block = true
	decision.WouldBlock = true
	decision.Reason = "enforced"
	return decision
}
