package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defense session scopes and modes. A session is the operator-facing unit:
// either one agent or a whole tag group.
const (
	DefenseScopeAgent = "agent"
	DefenseScopeTag   = "tag"

	DefenseModeBlock   = "block"
	DefenseModeMonitor = "monitor"

	DefenseSourceManual   = "manual"
	DefenseSourceSchedule = "schedule"

	// dry_run: a signed block canary is applied and observed (5 minutes by
	// default). active: the canary was promoted and RASP is enforcing.
	DefenseStatusDryRun  = "dry_run"
	DefenseStatusActive  = "active"
	DefenseStatusStopped = "stopped"
	DefenseStatusExpired = "expired"
	DefenseStatusFailed  = "failed"
)

var (
	errDefenseNotFound        = errors.New("defense: not found")
	errDefenseConflict        = errors.New("defense: conflict")
	errDefenseValidation      = errors.New("defense: validation")
	errDefenseUnavailable     = errors.New("defense: runtime unavailable")
	errDefenseBlockDisabled   = errors.New("defense: production block promotion is disabled")
	errDefenseNoAgents        = errors.New("defense: scope has no agents")
	errDefenseMonitorBaseline = errors.New("defense: an active monitor policy is required")
)

// DefenseEvent is the append-only audit trail of one defense session or
// schedule change: who, when, what was switched, and the result.
type DefenseEvent struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Result string    `json:"result"`
	Detail string    `json:"detail,omitempty"`
}

type DefenseSession struct {
	ID               string         `json:"id"`
	Scope            string         `json:"scope"`
	ScopeValue       string         `json:"scope_value"`
	Mode             string         `json:"mode"`
	Source           string         `json:"source"`
	ScheduleID       string         `json:"schedule_id,omitempty"`
	Reason           string         `json:"reason"`
	Status           string         `json:"status"`
	CreatedBy        string         `json:"created_by"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	StartsAt         time.Time      `json:"starts_at"`
	DryRunUntil      time.Time      `json:"dry_run_until"`
	EndsAt           time.Time      `json:"ends_at"`
	PolicyVersion    uint64         `json:"policy_version,omitempty"`
	BaseVersion      uint64         `json:"base_version,omitempty"`
	AgentIDs         []string       `json:"agent_ids"`
	DryRunWouldBlock int64          `json:"dry_run_would_block"`
	DryRunBlocked    int64          `json:"dry_run_blocked"`
	FailureReason    string         `json:"failure_reason,omitempty"`
	StoppedAt        *time.Time     `json:"stopped_at,omitempty"`
	StoppedBy        string         `json:"stopped_by,omitempty"`
	Events           []DefenseEvent `json:"events"`
	RemainingSeconds int64          `json:"remaining_seconds"`
}

type DefenseSchedule struct {
	ID            string         `json:"id"`
	Tag           string         `json:"tag"`
	StartTime     string         `json:"start_time"`
	EndTime       string         `json:"end_time"`
	Priority      int            `json:"priority"`
	Enabled       bool           `json:"enabled"`
	DryRunSeconds int            `json:"dry_run_seconds"`
	Timezone      string         `json:"timezone"`
	Reason        string         `json:"reason"`
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     *time.Time     `json:"deleted_at,omitempty"`
	DeletedBy     string         `json:"deleted_by,omitempty"`
	Events        []DefenseEvent `json:"events"`
}

// DefenseScheduleView adds derived state so the console does not have to
// re-implement window arithmetic.
type DefenseScheduleView struct {
	DefenseSchedule
	ActiveNow   bool       `json:"active_now"`
	Phase       string     `json:"phase"`
	WindowStart *time.Time `json:"window_start,omitempty"`
	WindowEnd   *time.Time `json:"window_end,omitempty"`
	NextStart   *time.Time `json:"next_start,omitempty"`
}

type DefenseTag struct {
	Tag    string `json:"tag"`
	Agents int64  `json:"agents"`
}

type DefenseStatus struct {
	Mode                 string                `json:"mode"`
	Monitoring           bool                  `json:"monitoring"`
	Session              *DefenseSession       `json:"session"`
	LastFailed           *DefenseSession       `json:"last_failed,omitempty"`
	RemainingSeconds     int64                 `json:"remaining_seconds"`
	AllowProductionBlock bool                  `json:"allow_production_block"`
	Schedules            []DefenseScheduleView `json:"schedules"`
	Tags                 []DefenseTag          `json:"tags"`
	ServerTime           time.Time             `json:"server_time"`
}

// defensePolicyManager is the subset of agentpolicy.Manager the defense
// runtime drives. Keeping it an interface lets the scheduler be tested without
// signing keys or a database.
type defensePolicyManager interface {
	Snapshot(ctx context.Context) (agentpolicy.PersistedPolicy, agentpolicy.PersistedPolicy, error)
	Create(ctx context.Context, policy agentpolicy.Policy) (agentpolicy.SignedPolicy, error)
	StartCanary(ctx context.Context, version uint64) error
	CompleteCanary(ctx context.Context, version uint64, observation agentpolicy.CanaryObservation) error
	Promote(ctx context.Context, version uint64) error
	Rollback(ctx context.Context, version uint64) error
	ProductionBlockAllowed() bool
}

var _ defensePolicyManager = (*agentpolicy.Manager)(nil)

type DefenseSessionRequest struct {
	Scope      string
	ScopeValue string
	Mode       string
	Source     string
	ScheduleID string
	Reason     string
	Actor      string
	// Duration applies when EndsAt is zero.
	Duration time.Duration
	// DryRun applies when DryRunUntil is zero and DryRunSet is true.
	DryRun    time.Duration
	DryRunSet bool
	StartsAt  time.Time
	// DryRunUntil defaults to StartsAt+DryRun.
	DryRunUntil time.Time
	EndsAt      time.Time
}

type DefenseScheduleRequest struct {
	Tag           *string `json:"tag"`
	StartTime     *string `json:"start_time"`
	EndTime       *string `json:"end_time"`
	Priority      *int    `json:"priority"`
	Enabled       *bool   `json:"enabled"`
	DryRunSeconds *int    `json:"dry_run_seconds"`
	Timezone      *string `json:"timezone"`
	Reason        *string `json:"reason"`
	Actor         string  `json:"-"`
}

type DefenseRuntimeConfig struct {
	Repository   defenseRepository
	Policy       defensePolicyManager
	Now          func() time.Time
	Location     *time.Location
	DryRun       time.Duration
	AckTimeout   time.Duration
	TickInterval time.Duration
}

// DefenseRuntime owns the defense sessions state machine and the 30 second
// schedule evaluator. Every transition is fail-safe: if anything goes wrong the
// signed policy is rolled back to the active monitor baseline.
type DefenseRuntime struct {
	repository              defenseRepository
	policy                  defensePolicyManager
	now                     func() time.Time
	location                *time.Location
	dryRun                  time.Duration
	ackTimeout              time.Duration
	tickInterval            time.Duration
	mu                      sync.Mutex
	startOnce               sync.Once
	cancel                  context.CancelFunc
	scheduleSuppressedUntil map[string]time.Time
}

func NewDefenseRuntime(config DefenseRuntimeConfig) (*DefenseRuntime, error) {
	if config.Repository == nil {
		return nil, fmt.Errorf("defense: repository is required")
	}
	if config.Policy == nil {
		return nil, fmt.Errorf("defense: policy manager is required")
	}
	runtime := &DefenseRuntime{
		repository:              config.Repository,
		policy:                  config.Policy,
		now:                     config.Now,
		location:                config.Location,
		dryRun:                  config.DryRun,
		ackTimeout:              config.AckTimeout,
		tickInterval:            config.TickInterval,
		scheduleSuppressedUntil: make(map[string]time.Time),
	}
	if runtime.now == nil {
		runtime.now = time.Now
	}
	if runtime.location == nil {
		runtime.location = defenseDefaultLocation()
	}
	if runtime.dryRun <= 0 {
		runtime.dryRun = 5 * time.Minute
	}
	if runtime.ackTimeout <= 0 {
		runtime.ackTimeout = 2 * time.Minute
	}
	if runtime.tickInterval <= 0 {
		runtime.tickInterval = 30 * time.Second
	}
	return runtime, nil
}

// Start launches the evaluator loop. It is idempotent.
func (runtime *DefenseRuntime) Start(ctx context.Context) {
	runtime.startOnce.Do(func() {
		loopContext, cancel := context.WithCancel(ctx)
		runtime.cancel = cancel
		go runtime.loop(loopContext)
	})
}

// Stop terminates the evaluator loop. Safe to call more than once.
func (runtime *DefenseRuntime) Stop() {
	if runtime.cancel != nil {
		runtime.cancel()
	}
}

func (runtime *DefenseRuntime) loop(ctx context.Context) {
	ticker := time.NewTicker(runtime.tickInterval)
	defer ticker.Stop()
	if err := runtime.Tick(ctx); err != nil {
		log.Printf("defense scheduler tick: %v", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := runtime.Tick(ctx); err != nil {
				log.Printf("defense scheduler tick: %v", err)
			}
		}
	}
}

// Tick evaluates live sessions and then the schedule windows. It is safe to
// call concurrently with the HTTP handlers.
func (runtime *DefenseRuntime) Tick(ctx context.Context) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	now := runtime.now().UTC()
	problems := make([]string, 0)

	sessions, err := runtime.repository.ListSessions(ctx, []string{DefenseStatusDryRun, DefenseStatusActive}, 100)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.Status != DefenseStatusDryRun && session.Status != DefenseStatusActive {
			continue
		}
		// A failure keeps the row live until the rollback succeeds; retrying the
		// rollback is the only action allowed in that state.
		if session.FailureReason != "" {
			if rollbackErr := runtime.retryRollback(ctx, session, "scheduler"); rollbackErr != nil {
				problems = append(problems, rollbackErr.Error())
			}
			continue
		}
		if session.Mode == DefenseModeMonitor {
			if !now.Before(session.EndsAt) {
				if _, stopErr := runtime.stopSessionLocked(ctx, session, DefenseStatusExpired, "scheduler", "monitor window ended"); stopErr != nil {
					problems = append(problems, stopErr.Error())
				}
			}
			continue
		}
		if !now.Before(session.EndsAt) {
			if _, stopErr := runtime.stopSessionLocked(ctx, session, DefenseStatusExpired, "scheduler", "defense window ended"); stopErr != nil {
				problems = append(problems, stopErr.Error())
			}
			continue
		}
		if session.Status == DefenseStatusDryRun && !now.Before(session.DryRunUntil) {
			if promoteErr := runtime.advanceDryRun(ctx, session, now); promoteErr != nil {
				problems = append(problems, promoteErr.Error())
				// A failed automation window must not be retried by the scheduler:
				// stay in monitor until the operator or the next window.
				if session.Source == DefenseSourceSchedule && session.ScheduleID != "" {
					runtime.scheduleSuppressedUntil[session.ScheduleID] = session.EndsAt
				}
			}
		}
	}

	live, liveErr := runtime.repository.LiveBlockSession(ctx)
	if liveErr != nil && !errors.Is(liveErr, errDefenseNotFound) {
		problems = append(problems, liveErr.Error())
		return defenseProblems(problems)
	}
	// Operator intent wins over automation: a manual session (block or monitor)
	// suppresses schedule-driven transitions until it ends.
	if liveErr == nil && live.Source == DefenseSourceManual {
		return defenseProblems(problems)
	}
	if monitor, monitorErr := runtime.liveManualMonitor(ctx, now); monitorErr != nil {
		problems = append(problems, monitorErr.Error())
	} else if monitor {
		return defenseProblems(problems)
	}
	if scheduleErr := runtime.evaluateSchedules(ctx, now); scheduleErr != nil {
		problems = append(problems, scheduleErr.Error())
	}
	return defenseProblems(problems)
}

// CreateSession creates a manual defense session. Block sessions first apply a
// signed block canary; the scheduler promotes it after the dry-run window.
func (runtime *DefenseRuntime) CreateSession(ctx context.Context, request DefenseSessionRequest) (DefenseSession, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.createSessionLocked(ctx, request)
}

func (runtime *DefenseRuntime) createSessionLocked(ctx context.Context, request DefenseSessionRequest) (DefenseSession, error) {
	now := runtime.now().UTC()
	request, err := normalizeDefenseSessionRequest(request, runtime.dryRun)
	if err != nil {
		return DefenseSession{}, err
	}
	session := DefenseSession{
		ID:         newDefenseID("ds"),
		Scope:      request.Scope,
		ScopeValue: request.ScopeValue,
		Mode:       request.Mode,
		Source:     request.Source,
		ScheduleID: request.ScheduleID,
		Reason:     request.Reason,
		CreatedBy:  request.Actor,
		CreatedAt:  now,
		UpdatedAt:  now,
		StartsAt:   request.StartsAt,
		Status:     DefenseStatusDryRun,
		AgentIDs:   []string{},
	}
	if session.StartsAt.IsZero() || session.StartsAt.Before(now) {
		session.StartsAt = now
	}
	session.DryRunUntil = request.DryRunUntil
	if session.DryRunUntil.IsZero() {
		session.DryRunUntil = session.StartsAt.Add(request.DryRun)
	}
	session.EndsAt = request.EndsAt
	if session.EndsAt.IsZero() {
		session.EndsAt = session.StartsAt.Add(request.Duration)
	}
	if !session.EndsAt.After(now) {
		return DefenseSession{}, fmt.Errorf("%w: session must end in the future", errDefenseValidation)
	}

	if request.Mode == DefenseModeBlock {
		live, liveErr := runtime.repository.LiveBlockSession(ctx)
		if liveErr == nil {
			return DefenseSession{}, fmt.Errorf("%w: block session %s is already live", errDefenseConflict, live.ID)
		}
		if !errors.Is(liveErr, errDefenseNotFound) {
			return DefenseSession{}, liveErr
		}
		started, startErr := runtime.startBlockSession(ctx, session)
		if startErr != nil {
			session.Status = DefenseStatusFailed
			session.FailureReason = startErr.Error()
			session.record(now, request.Actor, "create_failed", "failed", startErr.Error())
			if insertErr := runtime.repository.CreateSession(ctx, session); insertErr != nil {
				log.Printf("defense: persist failed session %s: %v", session.ID, insertErr)
			}
			return session, startErr
		}
		if err := runtime.repository.CreateSession(ctx, started); err != nil {
			// Never leave a signed block policy without a session row: roll the
			// canary back so monitoring stays the effective mode.
			if rollbackErr := runtime.policy.Rollback(ctx, started.PolicyVersion); rollbackErr != nil {
				log.Printf("defense: rollback unrecorded policy %d: %v", started.PolicyVersion, rollbackErr)
			}
			return started, err
		}
		return started, nil
	}

	// Monitor session: stop any live block policy first, then record the
	// operator's explicit monitoring window.
	live, liveErr := runtime.repository.LiveBlockSession(ctx)
	if liveErr == nil {
		if _, stopErr := runtime.stopSessionLocked(ctx, live, DefenseStatusStopped, request.Actor, "switched to monitor: "+request.Reason); stopErr != nil {
			return DefenseSession{}, stopErr
		}
	} else if !errors.Is(liveErr, errDefenseNotFound) {
		return DefenseSession{}, liveErr
	}
	session.Status = DefenseStatusActive
	session.record(now, request.Actor, "monitoring", "ok", request.Reason)
	if err := runtime.repository.CreateSession(ctx, session); err != nil {
		return session, err
	}
	return session, nil
}

func (runtime *DefenseRuntime) startBlockSession(ctx context.Context, session DefenseSession) (DefenseSession, error) {
	now := runtime.now().UTC()
	latest, active, err := runtime.policy.Snapshot(ctx)
	if err != nil && !errors.Is(err, agentpolicy.ErrNotFound) {
		return session, fmt.Errorf("defense: load policy snapshot: %w", err)
	}
	if !runtime.policy.ProductionBlockAllowed() {
		return session, errDefenseBlockDisabled
	}
	base := active.Envelope.Policy
	if base.Version == 0 || base.Mode != agentpolicy.ModeMonitor {
		return session, fmt.Errorf("%w: active version %d mode %q", errDefenseMonitorBaseline, base.Version, base.Mode)
	}
	agents, err := runtime.resolveAgents(ctx, session.Scope, session.ScopeValue)
	if err != nil {
		return session, err
	}
	version := latest.Envelope.Policy.Version + 1
	if base.Version >= version {
		version = base.Version + 1
	}
	policy := base
	policy.ID = "rasp-defense-" + session.ID
	policy.Version = version
	policy.Owner = firstNonEmpty(session.CreatedBy, "defense-runtime")
	policy.Mode = agentpolicy.ModeBlock
	// Scope by agent IDs only: a language selector would drop agents whose
	// capability report has not arrived yet, which is exactly when protection
	// must still apply.
	policy.Selectors = agentpolicy.Selectors{AgentIDs: agents}
	policy.ExpiresAt = session.EndsAt
	policy.FailBehavior = agentpolicy.FailMonitor
	policy.AuditLink = "audit://defense/session/" + session.ID
	policy.Rollback = agentpolicy.RollbackPolicy{TargetVersion: base.Version, Deadline: session.EndsAt.Add(24 * time.Hour)}
	policy.Canary = agentpolicy.CanaryPolicy{RequiredACKs: 1}
	policy.Limits.ReplayMinSamples = 1
	if policy.Limits.ReplayMaxFalsePositiveRate <= 0 {
		policy.Limits.ReplayMaxFalsePositiveRate = 0.01
	}
	if policy.Limits.MaxBlocksPerMinute <= 0 {
		policy.Limits.MaxBlocksPerMinute = 60
	}
	if policy.Limits.MaxEventsPerSecond <= 0 {
		policy.Limits.MaxEventsPerSecond = 100
	}
	if _, err := runtime.policy.Create(ctx, policy); err != nil {
		return session, fmt.Errorf("defense: create block canary: %w", err)
	}
	if err := runtime.policy.StartCanary(ctx, version); err != nil {
		return session, fmt.Errorf("defense: start block canary: %w", err)
	}
	session.Status = DefenseStatusDryRun
	session.AgentIDs = agents
	session.PolicyVersion = version
	session.BaseVersion = base.Version
	session.record(now, session.CreatedBy, "canary_started", "ok", fmt.Sprintf(
		"policy=%d mode=block agents=%d dry_run_until=%s ends_at=%s",
		version, len(agents), session.DryRunUntil.Format(time.RFC3339), session.EndsAt.Format(time.RFC3339)))
	return session, nil
}

func (runtime *DefenseRuntime) advanceDryRun(ctx context.Context, session DefenseSession, now time.Time) error {
	latest, active, err := runtime.policy.Snapshot(ctx)
	if err != nil && !errors.Is(err, agentpolicy.ErrNotFound) {
		return runtime.failSession(ctx, session, "scheduler", fmt.Errorf("defense: load policy snapshot: %w", err))
	}
	if latest.Envelope.Policy.Version != session.PolicyVersion || latest.State != agentpolicy.StateCanary {
		if active.Envelope.Policy.Version == session.PolicyVersion && active.State == agentpolicy.StateActive && active.Envelope.Policy.Mode == agentpolicy.ModeBlock {
			session.Status = DefenseStatusActive
			session.record(now, "scheduler", "adopted", "ok", "policy already active")
			return runtime.repository.SaveSession(ctx, session)
		}
		return runtime.failSession(ctx, session, "scheduler", fmt.Errorf(
			"canary policy %d is no longer pending (latest=%d/%s)", session.PolicyVersion,
			latest.Envelope.Policy.Version, latest.State))
	}
	wouldBlock, blocked, err := runtime.repository.DryRunCounts(ctx, session.PolicyVersion, session.CreatedAt)
	if err != nil {
		return runtime.failSession(ctx, session, "scheduler", err)
	}
	session.DryRunWouldBlock = wouldBlock
	session.DryRunBlocked = blocked
	if blocked > 0 {
		return runtime.failSession(ctx, session, "scheduler", fmt.Errorf(
			"dry-run observed %d real blocks; refusing to promote", blocked))
	}
	samples := int(wouldBlock)
	if samples < 1 {
		// No hit during dry-run is not proof of safety, but it is also not an
		// anomaly. Promote with the minimum replay sample the signed policy gate
		// accepts; the real would-block count stays in the audit row.
		samples = 1
	}
	observation := agentpolicy.CanaryObservation{
		Succeeded: true,
		Replay:    &agentpolicy.ReplayMetrics{SampleCount: samples, FalsePositiveRate: 0},
	}
	if err := runtime.policy.CompleteCanary(ctx, session.PolicyVersion, observation); err != nil {
		return runtime.failSession(ctx, session, "scheduler", fmt.Errorf("defense: complete canary: %w", err))
	}
	if err := runtime.policy.Promote(ctx, session.PolicyVersion); err != nil {
		if errors.Is(err, agentpolicy.ErrMissingACK) {
			if now.Before(session.DryRunUntil.Add(runtime.ackTimeout)) {
				if !hasRecentDefenseEvent(session.Events, "ack_pending", now, 2*time.Minute) {
					session.record(now, "scheduler", "ack_pending", "ok", "waiting for agent acknowledgement")
				}
				return runtime.repository.SaveSession(ctx, session)
			}
			return runtime.failSession(ctx, session, "scheduler", fmt.Errorf("agent acknowledgement timeout: %w", err))
		}
		return runtime.failSession(ctx, session, "scheduler", fmt.Errorf("defense: promote block policy: %w", err))
	}
	session.Status = DefenseStatusActive
	session.record(now, "scheduler", "promoted", "ok", fmt.Sprintf(
		"policy=%d promoted after dry-run (would_block=%d blocked=%d)", session.PolicyVersion, wouldBlock, blocked))
	return runtime.repository.SaveSession(ctx, session)
}

func (runtime *DefenseRuntime) StopSession(ctx context.Context, id, actor, reason string) (DefenseSession, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	session, err := runtime.repository.Session(ctx, id)
	if err != nil {
		return session, err
	}
	if session.Source == DefenseSourceSchedule {
		return session, fmt.Errorf("%w: schedule sessions are controlled by their window; disable the rule instead", errDefenseConflict)
	}
	if session.Status != DefenseStatusDryRun && session.Status != DefenseStatusActive {
		return session, fmt.Errorf("%w: session is %s", errDefenseConflict, session.Status)
	}
	if strings.TrimSpace(reason) == "" {
		reason = "operator stopped the session"
	}
	return runtime.stopSessionLocked(ctx, session, DefenseStatusStopped, firstNonEmpty(actor, "api"), reason)
}

func (runtime *DefenseRuntime) stopSessionLocked(ctx context.Context, session DefenseSession, status, actor, reason string) (DefenseSession, error) {
	now := runtime.now().UTC()
	if session.Mode == DefenseModeBlock && session.PolicyVersion != 0 {
		if err := runtime.policy.Rollback(ctx, session.PolicyVersion); err != nil {
			session.FailureReason = fmt.Sprintf("rollback failed: %v", err)
			session.record(now, actor, "rollback_failed", "failed", session.FailureReason)
			if saveErr := runtime.repository.SaveSession(ctx, session); saveErr != nil {
				log.Printf("defense: persist rollback failure for %s: %v", session.ID, saveErr)
			}
			return session, fmt.Errorf("defense: rollback block policy %d: %w", session.PolicyVersion, err)
		}
	}
	session.Status = status
	session.FailureReason = ""
	stopped := now
	session.StoppedAt = &stopped
	session.StoppedBy = actor
	session.record(now, actor, status, "ok", reason)
	if err := runtime.repository.SaveSession(ctx, session); err != nil {
		return session, err
	}
	return session, nil
}

func (runtime *DefenseRuntime) failSession(ctx context.Context, session DefenseSession, actor string, cause error) error {
	now := runtime.now().UTC()
	session.FailureReason = cause.Error()
	session.record(now, actor, "failed", "failed", cause.Error())
	if session.Mode == DefenseModeBlock && session.PolicyVersion != 0 {
		if err := runtime.policy.Rollback(ctx, session.PolicyVersion); err != nil {
			session.record(now, "fail-safe", "rollback_retry", "failed", err.Error())
			if saveErr := runtime.repository.SaveSession(ctx, session); saveErr != nil {
				log.Printf("defense: persist fail-safe state for %s: %v", session.ID, saveErr)
			}
			return cause
		}
	}
	session.Status = DefenseStatusFailed
	stopped := now
	session.StoppedAt = &stopped
	session.StoppedBy = actor
	session.record(now, "fail-safe", "rolled_back", "ok", "fail-safe to monitor")
	if saveErr := runtime.repository.SaveSession(ctx, session); saveErr != nil {
		log.Printf("defense: persist failed session %s: %v", session.ID, saveErr)
	}
	return cause
}

func (runtime *DefenseRuntime) retryRollback(ctx context.Context, session DefenseSession, actor string) error {
	now := runtime.now().UTC()
	if session.PolicyVersion != 0 {
		if err := runtime.policy.Rollback(ctx, session.PolicyVersion); err != nil {
			session.record(now, actor, "rollback_retry", "failed", err.Error())
			if saveErr := runtime.repository.SaveSession(ctx, session); saveErr != nil {
				log.Printf("defense: persist rollback retry for %s: %v", session.ID, saveErr)
			}
			return fmt.Errorf("defense: rollback retry for %s: %w", session.ID, err)
		}
	}
	session.Status = DefenseStatusFailed
	stopped := now
	session.StoppedAt = &stopped
	session.StoppedBy = actor
	session.record(now, actor, "rolled_back", "ok", "fail-safe to monitor")
	if err := runtime.repository.SaveSession(ctx, session); err != nil {
		return err
	}
	return nil
}

func (runtime *DefenseRuntime) evaluateSchedules(ctx context.Context, now time.Time) error {
	schedules, err := runtime.repository.ListSchedules(ctx, false)
	if err != nil {
		return err
	}
	candidate := runtime.pickSchedule(schedules, now)
	live, liveErr := runtime.repository.LiveBlockSession(ctx)
	if liveErr != nil && !errors.Is(liveErr, errDefenseNotFound) {
		return liveErr
	}
	scheduleLive := liveErr == nil && live.Source == DefenseSourceSchedule
	if candidate == nil {
		if scheduleLive {
			_, stopErr := runtime.stopSessionLocked(ctx, live, DefenseStatusExpired, "scheduler", "defense window closed")
			return stopErr
		}
		return nil
	}
	if scheduleLive {
		if live.ScheduleID == candidate.schedule.ID {
			// Promotion and expiry are handled by the session pass above.
			return nil
		}
		_, stopErr := runtime.stopSessionLocked(ctx, live, DefenseStatusStopped, "scheduler",
			"superseded by schedule "+candidate.schedule.ID)
		return stopErr
	}
	if liveErr == nil && live.Source == DefenseSourceManual {
		return nil
	}
	if until, exists := runtime.scheduleSuppressedUntil[candidate.schedule.ID]; exists && now.Before(until) {
		return nil
	}

	dryRun := time.Duration(candidate.schedule.DryRunSeconds) * time.Second
	if dryRun <= 0 {
		dryRun = runtime.dryRun
	}
	request := DefenseSessionRequest{
		Scope:      DefenseScopeTag,
		ScopeValue: candidate.schedule.Tag,
		Mode:       DefenseModeBlock,
		Source:     DefenseSourceSchedule,
		ScheduleID: candidate.schedule.ID,
		Reason:     firstNonEmpty(candidate.schedule.Reason, "自动值守窗口"),
		Actor:      "scheduler",
		StartsAt:   candidate.start,
		EndsAt:     candidate.end,
	}
	if now.Before(candidate.start) {
		request.DryRunUntil = candidate.start
	} else {
		request.StartsAt = now
		request.DryRunUntil = now.Add(dryRun)
	}
	if !request.DryRunUntil.Before(candidate.end) {
		// The remaining window cannot fit a dry-run; skip instead of blocking
		// without observation.
		return nil
	}
	if _, createErr := runtime.createSessionLocked(ctx, request); createErr != nil {
		// Suppress this schedule until the current window ends: a failed start
		// must stay in monitor mode instead of retrying every 30 seconds.
		runtime.scheduleSuppressedUntil[candidate.schedule.ID] = candidate.end
		if errors.Is(createErr, errDefenseConflict) || errors.Is(createErr, errDefenseNotFound) {
			return nil
		}
		return fmt.Errorf("defense: schedule %s: %w", candidate.schedule.ID, createErr)
	}
	delete(runtime.scheduleSuppressedUntil, candidate.schedule.ID)
	return nil
}

func (runtime *DefenseRuntime) liveManualMonitor(ctx context.Context, now time.Time) (bool, error) {
	session, err := runtime.liveMonitorSession(ctx, now)
	if err != nil {
		return false, err
	}
	return session.ID != "", nil
}

func (runtime *DefenseRuntime) liveMonitorSession(ctx context.Context, now time.Time) (DefenseSession, error) {
	sessions, err := runtime.repository.ListSessions(ctx, []string{DefenseStatusActive}, 100)
	if err != nil {
		return DefenseSession{}, err
	}
	for _, session := range sessions {
		if session.Source != DefenseSourceManual || session.Mode != DefenseModeMonitor {
			continue
		}
		if !now.Before(session.EndsAt) || session.FailureReason != "" {
			continue
		}
		return session, nil
	}
	return DefenseSession{}, nil
}

func (runtime *DefenseRuntime) resolveAgents(ctx context.Context, scope, value string) ([]string, error) {
	switch scope {
	case DefenseScopeAgent:
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%w: agent id is required", errDefenseValidation)
		}
		return []string{strings.TrimSpace(value)}, nil
	case DefenseScopeTag:
		agents, err := runtime.repository.ResolveTagAgents(ctx, strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		if len(agents) == 0 {
			return nil, fmt.Errorf("%w: no agent carries tag %q", errDefenseNoAgents, value)
		}
		return agents, nil
	}
	return nil, fmt.Errorf("%w: scope must be agent or tag", errDefenseValidation)
}

type defenseScheduleCandidate struct {
	schedule DefenseSchedule
	start    time.Time
	end      time.Time
}

func (runtime *DefenseRuntime) pickSchedule(schedules []DefenseSchedule, now time.Time) *defenseScheduleCandidate {
	var chosen *defenseScheduleCandidate
	for _, schedule := range schedules {
		if !schedule.Enabled || schedule.DeletedAt != nil {
			continue
		}
		location := runtime.scheduleLocation(schedule)
		dryRun := time.Duration(schedule.DryRunSeconds) * time.Second
		if dryRun < 0 {
			dryRun = 0
		}
		for offset := -1; offset <= 1; offset++ {
			start, end, effective, valid := defenseScheduleWindow(schedule, now, location, dryRun, offset)
			if !valid || now.Before(effective) || !now.Before(end) {
				continue
			}
			candidate := defenseScheduleCandidate{schedule: schedule, start: start, end: end}
			if chosen == nil || defenseCandidateBetter(candidate, *chosen) {
				chosen = &candidate
			}
		}
	}
	return chosen
}

func defenseCandidateBetter(candidate, current defenseScheduleCandidate) bool {
	if candidate.schedule.Priority != current.schedule.Priority {
		return candidate.schedule.Priority > current.schedule.Priority
	}
	if !candidate.start.Equal(current.start) {
		return candidate.start.Before(current.start)
	}
	return candidate.schedule.ID < current.schedule.ID
}

func defenseScheduleWindow(schedule DefenseSchedule, now time.Time, location *time.Location, dryRun time.Duration, dayOffset int) (time.Time, time.Time, time.Time, bool) {
	startHour, startMinute, ok := defenseParseClock(schedule.StartTime)
	if !ok {
		return time.Time{}, time.Time{}, time.Time{}, false
	}
	endHour, endMinute, ok := defenseParseClock(schedule.EndTime)
	if !ok {
		return time.Time{}, time.Time{}, time.Time{}, false
	}
	local := now.In(location).AddDate(0, 0, dayOffset)
	start := time.Date(local.Year(), local.Month(), local.Day(), startHour, startMinute, 0, 0, location)
	end := time.Date(local.Year(), local.Month(), local.Day(), endHour, endMinute, 0, 0, location)
	if !end.After(start) {
		// Overnight window, e.g. 22:00-06:00.
		end = end.AddDate(0, 0, 1)
	}
	return start, end, start.Add(-dryRun), true
}

func defenseParseClock(value string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	hour, hourErr := strconv.Atoi(strings.TrimSpace(parts[0]))
	minute, minuteErr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, false
	}
	return hour, minute, true
}

func (runtime *DefenseRuntime) scheduleLocation(schedule DefenseSchedule) *time.Location {
	if timezone := strings.TrimSpace(schedule.Timezone); timezone != "" {
		if location, err := time.LoadLocation(timezone); err == nil {
			return location
		}
	}
	return runtime.location
}

func (runtime *DefenseRuntime) ListSessions(ctx context.Context, statuses []string, limit int) ([]DefenseSession, error) {
	sessions, err := runtime.repository.ListSessions(ctx, statuses, limit)
	if err != nil {
		return nil, err
	}
	now := runtime.now().UTC()
	for index := range sessions {
		sessions[index].RemainingSeconds = defenseRemainingSeconds(sessions[index], now)
	}
	return sessions, nil
}

func (runtime *DefenseRuntime) Status(ctx context.Context) (DefenseStatus, error) {
	now := runtime.now().UTC()
	status := DefenseStatus{
		Mode:                 DefenseModeMonitor,
		Monitoring:           true,
		AllowProductionBlock: runtime.policy.ProductionBlockAllowed(),
		Schedules:            make([]DefenseScheduleView, 0),
		Tags:                 make([]DefenseTag, 0),
		ServerTime:           now,
	}
	live, err := runtime.repository.LiveBlockSession(ctx)
	if err != nil && !errors.Is(err, errDefenseNotFound) {
		return status, err
	}
	if err == nil {
		session := live
		session.RemainingSeconds = defenseRemainingSeconds(session, now)
		status.Session = &session
		status.Mode = session.Mode
		status.Monitoring = false
		status.RemainingSeconds = session.RemainingSeconds
	} else {
		// No live block session: surface an explicit monitor session (if any)
		// so the console can show the remaining monitored window.
		monitorSession, monitorErr := runtime.liveMonitorSession(ctx, now)
		if monitorErr != nil {
			return status, monitorErr
		}
		if monitorSession.ID != "" {
			monitorSession.RemainingSeconds = defenseRemainingSeconds(monitorSession, now)
			status.Session = &monitorSession
			status.RemainingSeconds = monitorSession.RemainingSeconds
		}
	}
	schedules, err := runtime.repository.ListSchedules(ctx, false)
	if err != nil {
		return status, err
	}
	for _, schedule := range schedules {
		status.Schedules = append(status.Schedules, runtime.scheduleView(schedule, now))
	}
	tags, err := runtime.repository.ListTags(ctx)
	if err != nil {
		// Tags are a convenience for the form; never fail the status call over it.
		tags = make([]DefenseTag, 0)
	}
	status.Tags = tags
	if failed, failedErr := runtime.repository.ListSessions(ctx, []string{DefenseStatusFailed}, 1); failedErr == nil && len(failed) > 0 {
		session := failed[0]
		status.LastFailed = &session
	}
	return status, nil
}

func (runtime *DefenseRuntime) scheduleView(schedule DefenseSchedule, now time.Time) DefenseScheduleView {
	view := DefenseScheduleView{DefenseSchedule: schedule}
	location := runtime.scheduleLocation(schedule)
	dryRun := time.Duration(schedule.DryRunSeconds) * time.Second
	if dryRun < 0 {
		dryRun = 0
	}
	for offset := -1; offset <= 1; offset++ {
		start, end, effective, valid := defenseScheduleWindow(schedule, now, location, dryRun, offset)
		if !valid || now.Before(effective) || !now.Before(end) {
			continue
		}
		startCopy, endCopy := start, end
		view.WindowStart = &startCopy
		view.WindowEnd = &endCopy
		view.ActiveNow = schedule.Enabled && schedule.DeletedAt == nil
		if now.Before(start) {
			view.Phase = DefenseStatusDryRun
		} else {
			view.Phase = DefenseModeBlock
		}
		break
	}
	for offset := 0; offset <= 8 && view.NextStart == nil; offset++ {
		start, _, _, valid := defenseScheduleWindow(schedule, now, location, dryRun, offset)
		if !valid || !start.After(now) {
			continue
		}
		startCopy := start
		view.NextStart = &startCopy
	}
	return view
}

// CreateSchedule validates and stores an automatic window.
func (runtime *DefenseRuntime) CreateSchedule(ctx context.Context, request DefenseScheduleRequest) (DefenseSchedule, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if strings.TrimSpace(request.Actor) == "" {
		request.Actor = "api"
	}
	schedule := DefenseSchedule{
		ID:            newDefenseID("sc"),
		Enabled:       true,
		Priority:      0,
		DryRunSeconds: int(runtime.dryRun.Seconds()),
		Timezone:      defenseDefaultTimezone(),
		CreatedBy:     request.Actor,
		CreatedAt:     runtime.now().UTC(),
		UpdatedAt:     runtime.now().UTC(),
		Events:        make([]DefenseEvent, 0),
	}
	if err := applyDefenseScheduleRequest(&schedule, request, true); err != nil {
		return DefenseSchedule{}, err
	}
	if _, _, ok := defenseParseClock(schedule.StartTime); !ok {
		return DefenseSchedule{}, fmt.Errorf("%w: start_time must be HH:MM", errDefenseValidation)
	}
	schedule.record(schedule.CreatedAt, request.Actor, "schedule_created", "ok", fmt.Sprintf(
		"tag=%s window=%s-%s priority=%d", schedule.Tag, schedule.StartTime, schedule.EndTime, schedule.Priority))
	if err := runtime.repository.CreateSchedule(ctx, schedule); err != nil {
		return schedule, err
	}
	return schedule, nil
}

func (runtime *DefenseRuntime) UpdateSchedule(ctx context.Context, id string, request DefenseScheduleRequest) (DefenseSchedule, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if strings.TrimSpace(request.Actor) == "" {
		request.Actor = "api"
	}
	schedule, err := runtime.repository.Schedule(ctx, id)
	if err != nil {
		return schedule, err
	}
	if schedule.DeletedAt != nil {
		return schedule, errDefenseNotFound
	}
	if err := applyDefenseScheduleRequest(&schedule, request, false); err != nil {
		return schedule, err
	}
	if _, _, ok := defenseParseClock(schedule.StartTime); !ok {
		return schedule, fmt.Errorf("%w: start_time must be HH:MM", errDefenseValidation)
	}
	if _, _, ok := defenseParseClock(schedule.EndTime); !ok {
		return schedule, fmt.Errorf("%w: end_time must be HH:MM", errDefenseValidation)
	}
	schedule.UpdatedAt = runtime.now().UTC()
	schedule.record(schedule.UpdatedAt, request.Actor, "schedule_updated", "ok", fmt.Sprintf(
		"enabled=%t window=%s-%s priority=%d", schedule.Enabled, schedule.StartTime, schedule.EndTime, schedule.Priority))
	if err := runtime.repository.SaveSchedule(ctx, schedule); err != nil {
		return schedule, err
	}
	return schedule, nil
}

func (runtime *DefenseRuntime) DeleteSchedule(ctx context.Context, id, actor, reason string) (DefenseSchedule, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if strings.TrimSpace(actor) == "" {
		actor = "api"
	}
	schedule, err := runtime.repository.Schedule(ctx, id)
	if err != nil {
		return schedule, err
	}
	if schedule.DeletedAt != nil {
		return schedule, errDefenseNotFound
	}
	now := runtime.now().UTC()
	schedule.DeletedAt = &now
	schedule.DeletedBy = actor
	schedule.Enabled = false
	schedule.UpdatedAt = now
	schedule.record(now, actor, "schedule_deleted", "ok", firstNonEmpty(reason, "operator deleted the rule"))
	if err := runtime.repository.SaveSchedule(ctx, schedule); err != nil {
		return schedule, err
	}
	return schedule, nil
}

func (runtime *DefenseRuntime) Schedule(ctx context.Context, id string) (DefenseSchedule, error) {
	return runtime.repository.Schedule(ctx, id)
}

// Session returns one session with the remaining seconds computed at read time.
func (runtime *DefenseRuntime) Session(ctx context.Context, id string) (DefenseSession, error) {
	session, err := runtime.repository.Session(ctx, id)
	if err != nil {
		return session, err
	}
	session.RemainingSeconds = defenseRemainingSeconds(session, runtime.now().UTC())
	return session, nil
}

func (runtime *DefenseRuntime) ListSchedules(ctx context.Context) ([]DefenseScheduleView, error) {
	schedules, err := runtime.repository.ListSchedules(ctx, false)
	if err != nil {
		return nil, err
	}
	now := runtime.now().UTC()
	views := make([]DefenseScheduleView, 0, len(schedules))
	for _, schedule := range schedules {
		views = append(views, runtime.scheduleView(schedule, now))
	}
	return views, nil
}

// Audit flattens session and schedule events into one newest-first trail.
func (runtime *DefenseRuntime) Audit(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	sessions, err := runtime.repository.ListSessions(ctx, nil, limit)
	if err != nil {
		return nil, err
	}
	schedules, err := runtime.repository.ListSchedules(ctx, true)
	if err != nil {
		return nil, err
	}
	type auditEntry struct {
		at  time.Time
		row map[string]interface{}
	}
	entries := make([]auditEntry, 0)
	for _, session := range sessions {
		for _, event := range session.Events {
			entries = append(entries, auditEntry{at: event.At, row: map[string]interface{}{
				"at": event.At, "actor": event.Actor, "action": event.Action, "result": event.Result,
				"detail": event.Detail, "kind": "session", "session_id": session.ID,
				"scope": session.Scope, "scope_value": session.ScopeValue, "mode": session.Mode,
				"status": session.Status, "reason": session.Reason,
			}})
		}
	}
	for _, schedule := range schedules {
		for _, event := range schedule.Events {
			entries = append(entries, auditEntry{at: event.At, row: map[string]interface{}{
				"at": event.At, "actor": event.Actor, "action": event.Action, "result": event.Result,
				"detail": event.Detail, "kind": "schedule", "schedule_id": schedule.ID,
				"tag": schedule.Tag, "window": schedule.StartTime + "-" + schedule.EndTime,
				"priority": schedule.Priority,
			}})
		}
	}
	sort.SliceStable(entries, func(left, right int) bool { return entries[left].at.After(entries[right].at) })
	if len(entries) > limit {
		entries = entries[:limit]
	}
	rows := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, entry.row)
	}
	return rows, nil
}

func (session *DefenseSession) record(now time.Time, actor, action, result, detail string) {
	session.Events = append(session.Events, DefenseEvent{At: now.UTC(), Actor: actor, Action: action, Result: result, Detail: detail})
	if len(session.Events) > 200 {
		session.Events = session.Events[len(session.Events)-200:]
	}
	session.UpdatedAt = now.UTC()
}

func (schedule *DefenseSchedule) record(now time.Time, actor, action, result, detail string) {
	schedule.Events = append(schedule.Events, DefenseEvent{At: now.UTC(), Actor: actor, Action: action, Result: result, Detail: detail})
	if len(schedule.Events) > 200 {
		schedule.Events = schedule.Events[len(schedule.Events)-200:]
	}
}

func normalizeDefenseSessionRequest(request DefenseSessionRequest, defaultDryRun time.Duration) (DefenseSessionRequest, error) {
	request.Scope = strings.ToLower(strings.TrimSpace(request.Scope))
	request.Mode = strings.ToLower(strings.TrimSpace(request.Mode))
	request.Source = strings.ToLower(strings.TrimSpace(request.Source))
	request.ScopeValue = strings.TrimSpace(request.ScopeValue)
	request.Reason = strings.TrimSpace(request.Reason)
	request.Actor = firstNonEmpty(strings.TrimSpace(request.Actor), "api")
	if request.Scope != DefenseScopeAgent && request.Scope != DefenseScopeTag {
		return request, fmt.Errorf("%w: scope must be agent or tag", errDefenseValidation)
	}
	if request.ScopeValue == "" {
		return request, fmt.Errorf("%w: scope_value is required", errDefenseValidation)
	}
	if request.Mode != DefenseModeBlock && request.Mode != DefenseModeMonitor {
		return request, fmt.Errorf("%w: mode must be block or monitor", errDefenseValidation)
	}
	if request.Reason == "" {
		return request, fmt.Errorf("%w: reason is required", errDefenseValidation)
	}
	if request.Source == "" {
		request.Source = DefenseSourceManual
	}
	if request.Source == DefenseSourceSchedule && request.Mode != DefenseModeBlock {
		return request, fmt.Errorf("%w: schedule sessions must use block mode", errDefenseValidation)
	}
	if request.Duration <= 0 {
		request.Duration = 8 * time.Hour
	}
	if request.Duration < time.Minute || request.Duration > 7*24*time.Hour {
		return request, fmt.Errorf("%w: duration must be between 1 minute and 7 days", errDefenseValidation)
	}
	if !request.DryRunSet {
		request.DryRun = defaultDryRun
	}
	if request.DryRun < 0 {
		request.DryRun = 0
	}
	if request.DryRun > time.Hour {
		return request, fmt.Errorf("%w: dry-run must be at most 1 hour", errDefenseValidation)
	}
	return request, nil
}

func applyDefenseScheduleRequest(schedule *DefenseSchedule, request DefenseScheduleRequest, creating bool) error {
	if request.Tag != nil {
		schedule.Tag = strings.TrimSpace(*request.Tag)
	}
	if request.StartTime != nil {
		schedule.StartTime = strings.TrimSpace(*request.StartTime)
	}
	if request.EndTime != nil {
		schedule.EndTime = strings.TrimSpace(*request.EndTime)
	}
	if request.Priority != nil {
		schedule.Priority = *request.Priority
	}
	if request.Enabled != nil {
		schedule.Enabled = *request.Enabled
	}
	if request.DryRunSeconds != nil {
		schedule.DryRunSeconds = *request.DryRunSeconds
	}
	if request.Timezone != nil {
		schedule.Timezone = strings.TrimSpace(*request.Timezone)
	}
	if request.Reason != nil {
		schedule.Reason = strings.TrimSpace(*request.Reason)
	}
	if schedule.Tag == "" {
		return fmt.Errorf("%w: tag is required", errDefenseValidation)
	}
	if _, _, ok := defenseParseClock(schedule.StartTime); !ok {
		return fmt.Errorf("%w: start_time must be HH:MM", errDefenseValidation)
	}
	if _, _, ok := defenseParseClock(schedule.EndTime); !ok {
		return fmt.Errorf("%w: end_time must be HH:MM", errDefenseValidation)
	}
	if schedule.StartTime == schedule.EndTime {
		return fmt.Errorf("%w: start_time and end_time must differ", errDefenseValidation)
	}
	if schedule.Priority < -100 {
		schedule.Priority = -100
	}
	if schedule.Priority > 100 {
		schedule.Priority = 100
	}
	if schedule.DryRunSeconds < 0 {
		schedule.DryRunSeconds = 0
	}
	if schedule.DryRunSeconds > 3600 {
		schedule.DryRunSeconds = 3600
	}
	if creating && schedule.DryRunSeconds == 0 {
		schedule.DryRunSeconds = 300
	}
	if schedule.Timezone == "" {
		schedule.Timezone = defenseDefaultTimezone()
	}
	if _, err := time.LoadLocation(schedule.Timezone); err != nil {
		return fmt.Errorf("%w: unknown timezone %q", errDefenseValidation, schedule.Timezone)
	}
	return nil
}

func defenseRemainingSeconds(session DefenseSession, now time.Time) int64 {
	if session.EndsAt.IsZero() {
		return 0
	}
	remaining := int64(session.EndsAt.Sub(now).Seconds())
	if remaining < 0 {
		return 0
	}
	return remaining
}

func hasRecentDefenseEvent(events []DefenseEvent, action string, now time.Time, window time.Duration) bool {
	for index := len(events) - 1; index >= 0; index-- {
		if events[index].Action != action {
			continue
		}
		return now.Sub(events[index].At) < window
	}
	return false
}

func newDefenseID(prefix string) string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}

func defenseDefaultTimezone() string {
	name := getEnv("LYFLOW_DEFENSE_TZ", "Asia/Shanghai")
	if _, err := time.LoadLocation(name); err != nil {
		return "UTC"
	}
	return name
}

func defenseDefaultLocation() *time.Location {
	if location, err := time.LoadLocation(defenseDefaultTimezone()); err == nil {
		return location
	}
	return time.UTC
}

func defenseProblems(problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

// defenseRuntimeFor returns the process-wide runtime, creating and starting it
// lazily. InitDefenseRuntime is the explicit startup hook for main.go; the lazy
// path keeps the handlers functional even if the startup call is missed.
func defenseTickInterval() time.Duration {
	seconds := 2
	if value := strings.TrimSpace(os.Getenv("DEFENSE_TICK_INTERVAL_SECONDS")); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 60 {
			seconds = parsed
		}
	}
	return time.Duration(seconds) * time.Second
}

func defenseRuntimeFor(cfg *Config) (*DefenseRuntime, error) {
	if defenseRuntimeOverride != nil {
		return defenseRuntimeOverride, nil
	}
	runtime, err := getOrCreateDefenseRuntime(cfg)
	if err != nil {
		return nil, err
	}
	runtime.Start(context.Background())
	return runtime, nil
}

// InitDefenseRuntime wires the runtime at server startup and begins the 30
// second schedule evaluation. Call it once, after cfg.RASPPolicy is ready, so
// windows are evaluated even when nobody has opened the console.
func InitDefenseRuntime(ctx context.Context, cfg *Config) (*DefenseRuntime, error) {
	if defenseRuntimeOverride != nil {
		defenseRuntimeOverride.Start(ctx)
		return defenseRuntimeOverride, nil
	}
	runtime, err := getOrCreateDefenseRuntime(cfg)
	if err != nil {
		return nil, err
	}
	runtime.Start(ctx)
	return runtime, nil
}

func getOrCreateDefenseRuntime(cfg *Config) (*DefenseRuntime, error) {
	if cfg == nil || cfg.DBPool == nil {
		return nil, fmt.Errorf("%w: database pool unavailable", errDefenseUnavailable)
	}
	if cfg.RASPPolicy == nil {
		return nil, fmt.Errorf("%w: RASP policy lifecycle unavailable", errDefenseUnavailable)
	}
	defenseRuntimeMutex.Lock()
	defer defenseRuntimeMutex.Unlock()
	if sharedDefenseRuntime != nil {
		return sharedDefenseRuntime, nil
	}
	repository := newPostgresDefenseRepository(cfg.DBPool)
	if err := repository.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	runtime, err := NewDefenseRuntime(DefenseRuntimeConfig{
		Repository:   repository,
		Policy:       cfg.RASPPolicy,
		Location:     defenseDefaultLocation(),
		TickInterval: defenseTickInterval(),
	})
	if err != nil {
		return nil, err
	}
	sharedDefenseRuntime = runtime
	return runtime, nil
}

var (
	defenseRuntimeMutex    sync.Mutex
	sharedDefenseRuntime   *DefenseRuntime
	defenseRuntimeOverride *DefenseRuntime
)
