package agentpolicy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
)

type Policy = shared.Policy
type SignedPolicy = shared.SignedPolicy
type Mode = shared.Mode
type Selectors = shared.Selectors
type Limits = shared.Limits
type CanaryPolicy = shared.CanaryPolicy
type RollbackPolicy = shared.RollbackPolicy
type FailBehavior = shared.FailBehavior
type Language = shared.Language

const (
	ModeOff     = shared.ModeOff
	ModeMonitor = shared.ModeMonitor
	ModeBlock   = shared.ModeBlock
	FailMonitor = shared.FailMonitor
	FailDisable = shared.FailDisable
)

var (
	ErrNotFound                = errors.New("rasp policy: not found")
	ErrSignature               = errors.New("rasp policy: invalid signature")
	ErrStaleVersion            = errors.New("rasp policy: stale version")
	ErrInvalidTransition       = errors.New("rasp policy: invalid lifecycle transition")
	ErrExpired                 = errors.New("rasp policy: expired")
	ErrSelectorMismatch        = errors.New("rasp policy: selector mismatch")
	ErrMissingACK              = errors.New("rasp policy: required acknowledgement missing")
	ErrCanaryFailed            = errors.New("rasp policy: canary failed")
	ErrReplayMetricsRequired   = errors.New("rasp policy: replay metrics required")
	ErrOwnerRequired           = errors.New("rasp policy: explicit owner required")
	ErrRollbackRequired        = errors.New("rasp policy: rollback policy required")
	ErrProductionBlockDisabled = errors.New("rasp policy: production block promotion disabled")
	ErrSameVersionReplacement  = errors.New("rasp policy: same-version replacement rejected")
)

func DefaultPolicy(now time.Time, owner, auditLink string) Policy {
	return Policy{
		ID: "rasp-monitor-default", Version: 1, Owner: owner, Mode: ModeMonitor,
		Selectors: Selectors{Languages: []Language{shared.LanguagePython, shared.LanguageJava}}, ExpiresAt: now.Add(365 * 24 * time.Hour), FailBehavior: FailMonitor,
		Limits: Limits{MaxEventsPerSecond: 100, ReplayMinSamples: 1000, ReplayMaxFalsePositiveRate: 0.01},
		Canary: CanaryPolicy{RequiredACKs: 1}, AuditLink: auditLink,
	}
}

func validatePolicy(policy Policy, now time.Time) error {
	if strings.TrimSpace(policy.ID) == "" || policy.Version == 0 || strings.TrimSpace(policy.AuditLink) == "" {
		return fmt.Errorf("identity, version, and audit link are required: %w", ErrInvalidTransition)
	}
	if strings.TrimSpace(policy.Owner) == "" {
		return ErrOwnerRequired
	}
	if !policy.ExpiresAt.After(now) {
		return ErrExpired
	}
	switch policy.Mode {
	case ModeOff, ModeMonitor, ModeBlock:
	default:
		return fmt.Errorf("mode %q: %w", policy.Mode, ErrInvalidTransition)
	}
	switch policy.FailBehavior {
	case FailMonitor, FailDisable:
	default:
		return fmt.Errorf("fail behavior %q: %w", policy.FailBehavior, ErrInvalidTransition)
	}
	if policy.Limits.MaxEventsPerSecond <= 0 || policy.Canary.RequiredACKs <= 0 {
		return fmt.Errorf("limits and required acknowledgements must be positive: %w", ErrInvalidTransition)
	}
	if policy.Mode == ModeBlock {
		if policy.FailBehavior != FailMonitor {
			return fmt.Errorf("block policy must fail to monitor: %w", ErrInvalidTransition)
		}
		if policy.Limits.MaxBlocksPerMinute <= 0 || policy.Limits.ReplayMinSamples <= 0 || policy.Limits.ReplayMaxFalsePositiveRate <= 0 {
			return fmt.Errorf("block and replay limits must be positive: %w", ErrInvalidTransition)
		}
		if policy.Rollback.TargetVersion == 0 || !policy.Rollback.Deadline.After(now) {
			return ErrRollbackRequired
		}
	}
	return nil
}
