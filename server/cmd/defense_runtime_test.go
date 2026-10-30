package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
)

type defenseTestClock struct {
	current time.Time
}

func (clock *defenseTestClock) Now() time.Time {
	return clock.current
}

func (clock *defenseTestClock) Set(value time.Time) {
	clock.current = value
}

type defenseDryRunCount struct {
	wouldBlock int64
	blocked    int64
}

type memoryDefenseRepository struct {
	sessions  map[string]DefenseSession
	schedules map[string]DefenseSchedule
	tags      map[string][]string
	counts    map[uint64]defenseDryRunCount
}

func newMemoryDefenseRepository() *memoryDefenseRepository {
	return &memoryDefenseRepository{
		sessions:  make(map[string]DefenseSession),
		schedules: make(map[string]DefenseSchedule),
		tags:      make(map[string][]string),
		counts:    make(map[uint64]defenseDryRunCount),
	}
}

func (repository *memoryDefenseRepository) EnsureSchema(context.Context) error { return nil }

func cloneDefenseSession(session DefenseSession) DefenseSession {
	session.AgentIDs = append([]string{}, session.AgentIDs...)
	session.Events = append([]DefenseEvent{}, session.Events...)
	if session.StoppedAt != nil {
		stopped := *session.StoppedAt
		session.StoppedAt = &stopped
	}
	return session
}

func cloneDefenseSchedule(schedule DefenseSchedule) DefenseSchedule {
	schedule.Events = append([]DefenseEvent{}, schedule.Events...)
	if schedule.DeletedAt != nil {
		deleted := *schedule.DeletedAt
		schedule.DeletedAt = &deleted
	}
	return schedule
}

func (repository *memoryDefenseRepository) CreateSession(_ context.Context, session DefenseSession) error {
	if _, exists := repository.sessions[session.ID]; exists {
		return errDefenseConflict
	}
	repository.sessions[session.ID] = cloneDefenseSession(session)
	return nil
}

func (repository *memoryDefenseRepository) SaveSession(_ context.Context, session DefenseSession) error {
	if _, exists := repository.sessions[session.ID]; !exists {
		return errDefenseNotFound
	}
	repository.sessions[session.ID] = cloneDefenseSession(session)
	return nil
}

func (repository *memoryDefenseRepository) Session(_ context.Context, id string) (DefenseSession, error) {
	session, exists := repository.sessions[id]
	if !exists {
		return DefenseSession{}, errDefenseNotFound
	}
	return cloneDefenseSession(session), nil
}

func (repository *memoryDefenseRepository) ListSessions(_ context.Context, statuses []string, limit int) ([]DefenseSession, error) {
	allowed := make(map[string]bool, len(statuses))
	for _, status := range statuses {
		allowed[status] = true
	}
	items := make([]DefenseSession, 0)
	for _, session := range repository.sessions {
		if len(allowed) > 0 && !allowed[session.Status] {
			continue
		}
		items = append(items, cloneDefenseSession(session))
	}
	sort.Slice(items, func(left, right int) bool { return items[left].CreatedAt.After(items[right].CreatedAt) })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (repository *memoryDefenseRepository) LiveBlockSession(context.Context) (DefenseSession, error) {
	var chosen DefenseSession
	found := false
	for _, session := range repository.sessions {
		if session.Mode != DefenseModeBlock {
			continue
		}
		if session.Status != DefenseStatusDryRun && session.Status != DefenseStatusActive {
			continue
		}
		if !found || session.CreatedAt.After(chosen.CreatedAt) {
			chosen = session
			found = true
		}
	}
	if !found {
		return DefenseSession{}, errDefenseNotFound
	}
	return cloneDefenseSession(chosen), nil
}

func (repository *memoryDefenseRepository) CreateSchedule(_ context.Context, schedule DefenseSchedule) error {
	if _, exists := repository.schedules[schedule.ID]; exists {
		return errDefenseConflict
	}
	repository.schedules[schedule.ID] = cloneDefenseSchedule(schedule)
	return nil
}

func (repository *memoryDefenseRepository) SaveSchedule(_ context.Context, schedule DefenseSchedule) error {
	if _, exists := repository.schedules[schedule.ID]; !exists {
		return errDefenseNotFound
	}
	repository.schedules[schedule.ID] = cloneDefenseSchedule(schedule)
	return nil
}

func (repository *memoryDefenseRepository) Schedule(_ context.Context, id string) (DefenseSchedule, error) {
	schedule, exists := repository.schedules[id]
	if !exists {
		return DefenseSchedule{}, errDefenseNotFound
	}
	return cloneDefenseSchedule(schedule), nil
}

func (repository *memoryDefenseRepository) ListSchedules(_ context.Context, includeDeleted bool) ([]DefenseSchedule, error) {
	items := make([]DefenseSchedule, 0)
	for _, schedule := range repository.schedules {
		if !includeDeleted && schedule.DeletedAt != nil {
			continue
		}
		items = append(items, cloneDefenseSchedule(schedule))
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Priority > items[right].Priority })
	return items, nil
}

func (repository *memoryDefenseRepository) ResolveTagAgents(_ context.Context, tag string) ([]string, error) {
	return append([]string{}, repository.tags[tag]...), nil
}

func (repository *memoryDefenseRepository) ListTags(context.Context) ([]DefenseTag, error) {
	items := make([]DefenseTag, 0, len(repository.tags))
	for tag, agents := range repository.tags {
		items = append(items, DefenseTag{Tag: tag, Agents: int64(len(agents))})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Tag < items[right].Tag })
	return items, nil
}

func (repository *memoryDefenseRepository) DryRunCounts(_ context.Context, policyVersion uint64, _ time.Time) (int64, int64, error) {
	count := repository.counts[policyVersion]
	return count.wouldBlock, count.blocked, nil
}

type fakeDefensePolicy struct {
	monitor      agentpolicy.PersistedPolicy
	latest       agentpolicy.PersistedPolicy
	active       agentpolicy.PersistedPolicy
	allow        bool
	acks         int
	created      []agentpolicy.Policy
	observations []agentpolicy.CanaryObservation

	createErr   error
	startErr    error
	promoteErr  error
	rollbackErr error
}

func newFakeDefensePolicy() *fakeDefensePolicy {
	monitorPolicy := agentpolicy.DefaultPolicy(
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), "test-owner", "audit://test/monitor")
	monitor := agentpolicy.PersistedPolicy{
		Envelope: agentpolicy.SignedPolicy{Policy: monitorPolicy},
		State:    agentpolicy.StateActive,
	}
	return &fakeDefensePolicy{monitor: monitor, latest: monitor, active: monitor, allow: true, acks: 1}
}

func (policy *fakeDefensePolicy) Snapshot(context.Context) (agentpolicy.PersistedPolicy, agentpolicy.PersistedPolicy, error) {
	return policy.latest, policy.active, nil
}

func (policy *fakeDefensePolicy) Create(_ context.Context, candidate agentpolicy.Policy) (agentpolicy.SignedPolicy, error) {
	if policy.createErr != nil {
		return agentpolicy.SignedPolicy{}, policy.createErr
	}
	policy.created = append(policy.created, candidate)
	policy.latest = agentpolicy.PersistedPolicy{
		Envelope: agentpolicy.SignedPolicy{Policy: candidate},
		State:    agentpolicy.StateDraft,
	}
	return policy.latest.Envelope, nil
}

func (policy *fakeDefensePolicy) StartCanary(_ context.Context, version uint64) error {
	if policy.startErr != nil {
		return policy.startErr
	}
	if policy.latest.Envelope.Policy.Version != version || policy.latest.State != agentpolicy.StateDraft {
		return agentpolicy.ErrInvalidTransition
	}
	policy.latest.State = agentpolicy.StateCanary
	return nil
}

func (policy *fakeDefensePolicy) CompleteCanary(_ context.Context, version uint64, observation agentpolicy.CanaryObservation) error {
	if policy.latest.Envelope.Policy.Version != version || policy.latest.State != agentpolicy.StateCanary {
		return agentpolicy.ErrInvalidTransition
	}
	policy.observations = append(policy.observations, observation)
	policy.latest.Canary = &observation
	return nil
}

func (policy *fakeDefensePolicy) Promote(_ context.Context, version uint64) error {
	if policy.promoteErr != nil {
		return policy.promoteErr
	}
	if policy.latest.Envelope.Policy.Version != version || policy.latest.State != agentpolicy.StateCanary {
		return agentpolicy.ErrInvalidTransition
	}
	if policy.acks < policy.latest.Envelope.Policy.Canary.RequiredACKs {
		return agentpolicy.ErrMissingACK
	}
	if policy.latest.Canary == nil || !policy.latest.Canary.Succeeded {
		return agentpolicy.ErrCanaryFailed
	}
	policy.latest.State = agentpolicy.StateActive
	policy.active = policy.latest
	return nil
}

func (policy *fakeDefensePolicy) Rollback(_ context.Context, version uint64) error {
	if policy.rollbackErr != nil {
		return policy.rollbackErr
	}
	if policy.latest.Envelope.Policy.Version != version {
		return agentpolicy.ErrNotFound
	}
	policy.latest.State = agentpolicy.StateRolledBack
	policy.active = policy.monitor
	return nil
}

func (policy *fakeDefensePolicy) ProductionBlockAllowed() bool { return policy.allow }

type defenseTestFixture struct {
	runtime    *DefenseRuntime
	policy     *fakeDefensePolicy
	repository *memoryDefenseRepository
	clock      *defenseTestClock
}

func newDefenseTestFixture(t *testing.T, start time.Time) *defenseTestFixture {
	t.Helper()
	clock := &defenseTestClock{current: start}
	repository := newMemoryDefenseRepository()
	repository.tags["tag-a"] = []string{"agent-a1", "agent-a2"}
	repository.tags["tag-b"] = []string{"agent-b1"}
	policy := newFakeDefensePolicy()
	runtime, err := NewDefenseRuntime(DefenseRuntimeConfig{
		Repository:   repository,
		Policy:       policy,
		Now:          clock.Now,
		Location:     time.UTC,
		DryRun:       5 * time.Minute,
		AckTimeout:   2 * time.Minute,
		TickInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("new defense runtime: %v", err)
	}
	return &defenseTestFixture{runtime: runtime, policy: policy, repository: repository, clock: clock}
}

func (fixture *defenseTestFixture) createSchedule(t *testing.T, tag, start, end string, priority int) DefenseSchedule {
	t.Helper()
	timezone := "UTC"
	reason := "test window"
	schedule, err := fixture.runtime.CreateSchedule(context.Background(), DefenseScheduleRequest{
		Tag:       &tag,
		StartTime: &start,
		EndTime:   &end,
		Priority:  &priority,
		Timezone:  &timezone,
		Reason:    &reason,
		Actor:     "user:1",
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	return schedule
}

func defenseTestTime(hour, minute int) time.Time {
	return time.Date(2026, 1, 5, hour, minute, 0, 0, time.UTC)
}

func TestDefenseSchedulerDryRunPromoteAndExpire(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(9, 56))
	fixture.createSchedule(t, "tag-a", "10:00", "11:00", 5)
	ctx := context.Background()

	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("tick at pre-window: %v", err)
	}
	live, err := fixture.repository.LiveBlockSession(ctx)
	if err != nil {
		t.Fatalf("expected a dry-run session: %v", err)
	}
	if live.Status != DefenseStatusDryRun || live.Scope != DefenseScopeTag || live.ScopeValue != "tag-a" {
		t.Fatalf("unexpected session: %#v", live)
	}
	if len(live.AgentIDs) != 2 || live.PolicyVersion != 2 {
		t.Fatalf("expected 2 agents and policy version 2, got %#v", live)
	}
	if !live.DryRunUntil.Equal(defenseTestTime(10, 0)) || !live.EndsAt.Equal(defenseTestTime(11, 0)) {
		t.Fatalf("dry-run must span the pre-window lead: %#v", live)
	}
	if fixture.policy.latest.State != agentpolicy.StateCanary {
		t.Fatalf("policy must be a canary before promotion, got %s", fixture.policy.latest.State)
	}
	fixture.repository.counts[2] = defenseDryRunCount{wouldBlock: 3}

	fixture.clock.Set(defenseTestTime(10, 0).Add(30 * time.Second))
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("tick at window start: %v", err)
	}
	session, err := fixture.repository.Session(ctx, live.ID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if session.Status != DefenseStatusActive {
		t.Fatalf("session should be active after dry-run, got %s (%s)", session.Status, session.FailureReason)
	}
	if fixture.policy.active.Envelope.Policy.Version != 2 || fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeBlock {
		t.Fatalf("block policy should be active, got %#v", fixture.policy.active.Envelope.Policy)
	}
	if session.DryRunWouldBlock != 3 {
		t.Fatalf("dry-run would-block must be audited, got %d", session.DryRunWouldBlock)
	}
	lastObservation := fixture.policy.observations[len(fixture.policy.observations)-1]
	if lastObservation.Replay == nil || lastObservation.Replay.SampleCount != 3 {
		t.Fatalf("replay sample count must use observed would-block hits: %#v", lastObservation)
	}

	fixture.clock.Set(defenseTestTime(11, 0).Add(30 * time.Second))
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("tick after window: %v", err)
	}
	session, err = fixture.repository.Session(ctx, live.ID)
	if err != nil {
		t.Fatalf("load expired session: %v", err)
	}
	if session.Status != DefenseStatusExpired {
		t.Fatalf("session should expire with the window, got %s", session.Status)
	}
	if fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeMonitor {
		t.Fatalf("monitor policy must be restored, got %s", fixture.policy.active.Envelope.Policy.Mode)
	}
}

func TestDefenseScheduleOverlapUsesHighestPriority(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(10, 10))
	fixture.createSchedule(t, "tag-a", "10:00", "11:00", 1)
	fixture.createSchedule(t, "tag-b", "10:00", "11:00", 9)
	ctx := context.Background()

	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	live, err := fixture.repository.LiveBlockSession(ctx)
	if err != nil {
		t.Fatalf("expected a session: %v", err)
	}
	if live.ScopeValue != "tag-b" {
		t.Fatalf("highest priority window must win, got %#v", live)
	}
}

func TestDefenseScheduleTakeoverStopsLowerPriority(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(10, 10))
	fixture.createSchedule(t, "tag-a", "10:00", "11:00", 1)
	fixture.createSchedule(t, "tag-b", "10:30", "11:30", 9)
	ctx := context.Background()

	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	low, err := fixture.repository.LiveBlockSession(ctx)
	if err != nil || low.ScopeValue != "tag-a" {
		t.Fatalf("expected tag-a session first, got %#v (%v)", low, err)
	}

	fixture.clock.Set(defenseTestTime(10, 30).Add(30 * time.Second))
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("takeover tick: %v", err)
	}
	stopped, err := fixture.repository.Session(ctx, low.ID)
	if err != nil {
		t.Fatalf("load stopped session: %v", err)
	}
	if stopped.Status != DefenseStatusStopped {
		t.Fatalf("lower priority session must be stopped, got %s", stopped.Status)
	}
	if fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeMonitor {
		t.Fatalf("monitor policy must be restored during takeover")
	}

	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("create tick: %v", err)
	}
	live, err := fixture.repository.LiveBlockSession(ctx)
	if err != nil {
		t.Fatalf("expected the higher priority session: %v", err)
	}
	if live.ScopeValue != "tag-b" {
		t.Fatalf("higher priority window must take over, got %#v", live)
	}
}

func TestDefenseAckTimeoutFailsBackToMonitor(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(9, 56))
	fixture.policy.acks = 0
	fixture.createSchedule(t, "tag-a", "10:00", "11:00", 5)
	ctx := context.Background()

	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("pre-window tick: %v", err)
	}
	live, err := fixture.repository.LiveBlockSession(ctx)
	if err != nil {
		t.Fatalf("expected dry-run session: %v", err)
	}

	fixture.clock.Set(defenseTestTime(10, 0).Add(30 * time.Second))
	_ = fixture.runtime.Tick(ctx)
	session, err := fixture.repository.Session(ctx, live.ID)
	if err != nil {
		t.Fatalf("load waiting session: %v", err)
	}
	if session.Status != DefenseStatusDryRun {
		t.Fatalf("missing ACK must keep the dry-run waiting, got %s", session.Status)
	}

	fixture.clock.Set(defenseTestTime(10, 3))
	if err := fixture.runtime.Tick(ctx); err == nil {
		t.Fatal("ack timeout must be reported")
	}
	session, err = fixture.repository.Session(ctx, live.ID)
	if err != nil {
		t.Fatalf("load failed session: %v", err)
	}
	if session.Status != DefenseStatusFailed {
		t.Fatalf("session must fail back to monitor, got %s", session.Status)
	}
	if !strings.Contains(session.FailureReason, "acknowledgement timeout") {
		t.Fatalf("failure reason must explain the ACK timeout, got %q", session.FailureReason)
	}
	if fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeMonitor {
		t.Fatalf("monitor policy must be restored after ACK timeout")
	}
	if _, err := fixture.repository.LiveBlockSession(ctx); err == nil {
		t.Fatal("no block session may stay live after the failure")
	}
	// The scheduler must not retry the same window after a failure.
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("post-failure tick: %v", err)
	}
	if _, err := fixture.repository.LiveBlockSession(ctx); err == nil {
		t.Fatal("failed window must stay suppressed until the next window")
	}
	status, err := fixture.runtime.Status(ctx)
	if err != nil {
		t.Fatalf("status after failure: %v", err)
	}
	if status.LastFailed == nil || status.LastFailed.ID != live.ID {
		t.Fatalf("status must surface the last failed session: %#v", status.LastFailed)
	}
}

func TestDefenseDryRunRealBlocksFailBackToMonitor(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(9, 56))
	fixture.createSchedule(t, "tag-a", "10:00", "11:00", 5)
	ctx := context.Background()
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("pre-window tick: %v", err)
	}
	live, err := fixture.repository.LiveBlockSession(ctx)
	if err != nil {
		t.Fatalf("expected dry-run session: %v", err)
	}
	fixture.repository.counts[live.PolicyVersion] = defenseDryRunCount{wouldBlock: 1, blocked: 2}
	fixture.clock.Set(defenseTestTime(10, 0).Add(30 * time.Second))
	_ = fixture.runtime.Tick(ctx)
	session, err := fixture.repository.Session(ctx, live.ID)
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if session.Status != DefenseStatusFailed || !strings.Contains(session.FailureReason, "real blocks") {
		t.Fatalf("dry-run anomaly must fail-safe: %#v", session)
	}
	if fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeMonitor {
		t.Fatal("monitor policy must be restored")
	}
}

func TestDefenseManualSessionPromoteAndStop(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(8, 0))
	ctx := context.Background()
	session, err := fixture.runtime.CreateSession(ctx, DefenseSessionRequest{
		Scope:      DefenseScopeAgent,
		ScopeValue: "agent-a1",
		Mode:       DefenseModeBlock,
		Duration:   time.Hour,
		DryRun:     0,
		DryRunSet:  true,
		Reason:     "manual switch to block",
		Actor:      "user:7",
	})
	if err != nil {
		t.Fatalf("create manual session: %v", err)
	}
	if session.Status != DefenseStatusDryRun {
		t.Fatalf("a block session starts with a canary, got %s", session.Status)
	}
	fixture.clock.Set(defenseTestTime(8, 0).Add(30 * time.Second))
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("promote tick: %v", err)
	}
	session, err = fixture.repository.Session(ctx, session.ID)
	if err != nil {
		t.Fatalf("load promoted session: %v", err)
	}
	if session.Status != DefenseStatusActive {
		t.Fatalf("manual session must promote after ACK, got %s (%s)", session.Status, session.FailureReason)
	}
	stopped, err := fixture.runtime.StopSession(ctx, session.ID, "user:9", "back to monitoring")
	if err != nil {
		t.Fatalf("stop session: %v", err)
	}
	if stopped.Status != DefenseStatusStopped || stopped.StoppedBy != "user:9" {
		t.Fatalf("unexpected stopped session: %#v", stopped)
	}
	if fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeMonitor {
		t.Fatal("monitor policy must be restored after manual stop")
	}
	if _, err := fixture.runtime.StopSession(ctx, session.ID, "user:9", "again"); err == nil {
		t.Fatal("stopping a stopped session must conflict")
	}
}

func TestDefenseMonitorSessionSuppressesScheduler(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(10, 0))
	fixture.createSchedule(t, "tag-a", "10:00", "11:00", 5)
	ctx := context.Background()
	monitor, err := fixture.runtime.CreateSession(ctx, DefenseSessionRequest{
		Scope:      DefenseScopeTag,
		ScopeValue: "tag-a",
		Mode:       DefenseModeMonitor,
		Duration:   2 * time.Hour,
		Reason:     "operator stays in monitor mode",
		Actor:      "user:2",
	})
	if err != nil {
		t.Fatalf("create monitor session: %v", err)
	}
	if monitor.Status != DefenseStatusActive || monitor.Mode != DefenseModeMonitor {
		t.Fatalf("unexpected monitor session: %#v", monitor)
	}
	if err := fixture.runtime.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if _, err := fixture.repository.LiveBlockSession(ctx); err == nil {
		t.Fatal("manual monitor session must suppress schedule blocking")
	}
	status, err := fixture.runtime.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Monitoring || status.Session == nil || status.Session.ID != monitor.ID {
		t.Fatalf("status must surface the live monitor session: %#v", status)
	}
	if status.RemainingSeconds <= 0 {
		t.Fatalf("monitor session remaining time must be positive, got %d", status.RemainingSeconds)
	}
}

func TestDefenseBlockDisabledFailsSafe(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(8, 0))
	fixture.policy.allow = false
	ctx := context.Background()
	session, err := fixture.runtime.CreateSession(ctx, DefenseSessionRequest{
		Scope:      DefenseScopeAgent,
		ScopeValue: "agent-a1",
		Mode:       DefenseModeBlock,
		Duration:   time.Hour,
		Reason:     "block without operator opt-in",
		Actor:      "user:3",
	})
	if err == nil {
		t.Fatal("block must be rejected when production block is disabled")
	}
	if session.Status != DefenseStatusFailed || !strings.Contains(session.FailureReason, "disabled") {
		t.Fatalf("rejection must be audited as failed: %#v", session)
	}
	stored, loadErr := fixture.repository.Session(ctx, session.ID)
	if loadErr != nil {
		t.Fatalf("failed session must be persisted for audit: %v", loadErr)
	}
	if stored.CreatedBy != "user:3" {
		t.Fatalf("audit must record who asked: %#v", stored)
	}
	if fixture.policy.active.Envelope.Policy.Mode != agentpolicy.ModeMonitor {
		t.Fatal("rejection must leave monitoring in place")
	}
}

func TestDefenseScheduleWindowOvernight(t *testing.T) {
	schedule := DefenseSchedule{StartTime: "22:00", EndTime: "06:00"}
	start, end, effective, ok := defenseScheduleWindow(schedule, defenseTestTime(23, 30), time.UTC, 5*time.Minute, 0)
	if !ok || !start.Equal(defenseTestTime(22, 0)) || !end.Equal(defenseTestTime(6, 0).AddDate(0, 0, 1)) {
		t.Fatalf("unexpected overnight window: %s -> %s (%v)", start, end, ok)
	}
	if !effective.Equal(defenseTestTime(21, 55)) {
		t.Fatalf("dry-run lead must start at 21:55, got %s", effective)
	}

	// 02:00 belongs to the previous day's window.
	fixture := newDefenseTestFixture(t, defenseTestTime(2, 0))
	scheduleRecord := fixture.createSchedule(t, "tag-a", "22:00", "06:00", 0)
	candidate := fixture.runtime.pickSchedule([]DefenseSchedule{scheduleRecord}, defenseTestTime(2, 0))
	if candidate == nil {
		t.Fatal("overnight window must still be active after midnight")
	}
	if !candidate.start.Equal(defenseTestTime(22, 0).AddDate(0, 0, -1)) {
		t.Fatalf("overnight start must be yesterday 22:00, got %s", candidate.start)
	}
}

func TestDefenseSessionRemainingSeconds(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(8, 0))
	ctx := context.Background()
	session, err := fixture.runtime.CreateSession(ctx, DefenseSessionRequest{
		Scope:      DefenseScopeAgent,
		ScopeValue: "agent-a1",
		Mode:       DefenseModeMonitor,
		Duration:   90 * time.Minute,
		Reason:     "maintenance window",
		Actor:      "user:4",
	})
	if err != nil {
		t.Fatalf("create monitor session: %v", err)
	}
	status, err := fixture.runtime.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Session == nil || status.Session.ID != session.ID {
		t.Fatalf("status must include the monitor session: %#v", status)
	}
	if status.RemainingSeconds != int64(90*time.Minute/time.Second) {
		t.Fatalf("remaining seconds = %d", status.RemainingSeconds)
	}
}

func TestDefenseSchedulesHandlerCreatesAndLists(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(8, 0))
	previous := defenseRuntimeOverride
	defenseRuntimeOverride = fixture.runtime
	t.Cleanup(func() { defenseRuntimeOverride = previous })

	payload := []byte(`{"tag":"tag-a","start_time":"10:00","end_time":"11:00","priority":3,"reason":"auto window"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/defense/schedules", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	defenseSchedulesHandler(&Config{}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create schedule status = %d body=%s", recorder.Code, recorder.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/defense/schedules", nil)
	listRecorder := httptest.NewRecorder()
	defenseSchedulesHandler(&Config{}).ServeHTTP(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list schedule status = %d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Items []DefenseScheduleView `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode schedule list: %v", err)
	}
	if len(envelope.Data.Items) != 1 || envelope.Data.Items[0].Tag != "tag-a" {
		t.Fatalf("unexpected schedule list: %#v", envelope.Data.Items)
	}
}

func TestDefenseSessionsHandlerCreatesSession(t *testing.T) {
	fixture := newDefenseTestFixture(t, defenseTestTime(8, 0))
	previous := defenseRuntimeOverride
	defenseRuntimeOverride = fixture.runtime
	t.Cleanup(func() { defenseRuntimeOverride = previous })

	payload := []byte(`{"scope":"agent","scope_value":"agent-a1","mode":"block","duration_seconds":3600,"dry_run_seconds":0,"reason":"manual test"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/defense/sessions", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	defenseSessionsHandler(&Config{}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create session status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data DefenseSession `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if envelope.Data.Scope != DefenseScopeAgent || envelope.Data.Status != DefenseStatusDryRun {
		t.Fatalf("unexpected created session: %#v", envelope.Data)
	}

	stopRequest := httptest.NewRequest(http.MethodPost, "/api/v1/defense/sessions/"+envelope.Data.ID+"/stop", bytes.NewReader([]byte(`{"reason":"done"}`)))
	stopRecorder := httptest.NewRecorder()
	defenseSessionActionHandler(&Config{}).ServeHTTP(stopRecorder, stopRequest)
	if stopRecorder.Code != http.StatusOK {
		t.Fatalf("stop session status = %d body=%s", stopRecorder.Code, stopRecorder.Body.String())
	}
}
