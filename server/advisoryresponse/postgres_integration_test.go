package advisoryresponse

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPostgresStore_fake_verification_two_person_approval_persists_and_is_idempotent(t *testing.T) {
	// Given
	store, pool, ctx, now := newAdvisoryTestStore(t, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), true)
	requester := Actor{ID: "user:7", Role: RoleAnalyst}
	approver := Actor{ID: "user:8", Role: RoleAdmin}
	advisory, err := store.Submit(ctx, SubmitCommand{Candidate: testCandidate(t), Actor: requester, IdempotencyKey: "submit-1"})
	if err != nil {
		t.Fatalf("submit advisory: %v", err)
	}
	adapter := newFakeSimulationAdapter()
	if _, err := store.Verify(ctx, VerifyCommand{AdvisoryID: advisory.ID, Actor: Actor{ID: "qa:fake", Role: RoleVerifier}, IdempotencyKey: "verify-1", Adapter: adapter}); err != nil {
		t.Fatalf("verify advisory: %v", err)
	}

	// When
	approved, err := store.Approve(ctx, ApprovalCommand{AdvisoryID: advisory.ID, Actor: approver, IdempotencyKey: "approve-1"})
	if err != nil {
		t.Fatalf("approve advisory: %v", err)
	}
	replay, err := NewPostgresStore(pool, func() time.Time { return now }, DefaultLimits()).Approve(ctx, ApprovalCommand{AdvisoryID: advisory.ID, Actor: approver, IdempotencyKey: "approve-1"})

	// Then
	if err != nil {
		t.Fatalf("replay approval: %v", err)
	}
	if approved.Status != StatusApproved || replay.Status != StatusApproved || approved.ApprovedBy != approver.ID {
		t.Fatalf("approval/replay=%+v / %+v", approved, replay)
	}
	adapter.assertInertRollback(t)
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM response_advisory_audit WHERE advisory_id=$1`, advisory.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount != 3 {
		t.Fatalf("audit rows=%d, want submit+verify+approve", auditCount)
	}
	if _, err := pool.Exec(ctx, `UPDATE response_advisory_audit SET outcome='rejected' WHERE advisory_id=$1`, advisory.ID); err == nil {
		t.Fatal("advisory audit accepted mutation")
	}
}

func TestPostgresStore_denies_self_approval_stale_incident_unhealthy_agent_and_missing_verification(t *testing.T) {
	tests := []struct {
		name         string
		lastSeen     time.Time
		agentHealthy bool
		verify       bool
		approver     Actor
		want         error
	}{
		{name: "self approval", lastSeen: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), agentHealthy: true, verify: true, approver: Actor{ID: "user:7", Role: RoleAnalyst}, want: ErrTwoPersonRequired},
		{name: "stale incident", lastSeen: time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC), agentHealthy: true, verify: true, approver: Actor{ID: "user:8", Role: RoleAdmin}, want: ErrStaleIncident},
		{name: "unhealthy Agent", lastSeen: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), agentHealthy: false, verify: true, approver: Actor{ID: "user:8", Role: RoleAdmin}, want: ErrAgentUnhealthy},
		{name: "missing verification", lastSeen: time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), agentHealthy: true, verify: false, approver: Actor{ID: "user:8", Role: RoleAdmin}, want: ErrVerificationRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			store, pool, ctx, _ := newAdvisoryTestStore(t, test.lastSeen, test.agentHealthy)
			advisory, err := store.Submit(ctx, SubmitCommand{Candidate: testCandidate(t), Actor: Actor{ID: "user:7", Role: RoleAnalyst}, IdempotencyKey: "submit-" + test.name})
			if err != nil {
				t.Fatalf("submit advisory: %v", err)
			}
			if test.verify {
				if _, err := store.Verify(ctx, VerifyCommand{AdvisoryID: advisory.ID, Actor: Actor{ID: "qa:fake", Role: RoleVerifier}, IdempotencyKey: "verify-" + test.name, Adapter: newFakeSimulationAdapter()}); err != nil {
					t.Fatalf("verify advisory: %v", err)
				}
			}

			// When
			_, err = store.Approve(ctx, ApprovalCommand{AdvisoryID: advisory.ID, Actor: test.approver, IdempotencyKey: "approve-" + test.name})

			// Then
			if !errors.Is(err, test.want) {
				t.Fatalf("approval error=%v, want %v", err, test.want)
			}
			var status string
			if err := pool.QueryRow(ctx, `SELECT status FROM response_advisories WHERE id=$1`, advisory.ID).Scan(&status); err != nil {
				t.Fatalf("read advisory status: %v", err)
			}
			if status == string(StatusApproved) {
				t.Fatal("denied advisory was approved")
			}
			var outcome string
			if err := pool.QueryRow(ctx, `SELECT outcome FROM response_advisory_audit WHERE idempotency_key=$1`, "approve-"+test.name).Scan(&outcome); err != nil {
				t.Fatalf("read denial audit: %v", err)
			}
			if outcome != "rejected" {
				t.Fatalf("denial audit outcome=%q", outcome)
			}
		})
	}
}

func TestPostgresStore_concurrent_submit_idempotency_creates_one_advisory(t *testing.T) {
	// Given
	store, pool, ctx, _ := newAdvisoryTestStore(t, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), true)
	const workers = 8
	start := make(chan struct{})
	errorsByWorker := make(chan error, workers)
	candidate := testCandidate(t)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			<-start
			_, err := store.Submit(ctx, SubmitCommand{Candidate: candidate, Actor: Actor{ID: "user:7", Role: RoleAnalyst}, IdempotencyKey: "concurrent-submit"})
			errorsByWorker <- err
		}()
	}

	// When
	close(start)
	wait.Wait()
	close(errorsByWorker)

	// Then
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("idempotent submit: %v", err)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM response_advisories`).Scan(&rows); err != nil {
		t.Fatalf("count advisories: %v", err)
	}
	if rows != 1 {
		t.Fatalf("advisory rows=%d, want 1", rows)
	}
}

func TestPostgresSchema_rejects_shadow_provenance(t *testing.T) {
	// Given
	_, pool, ctx, now := newAdvisoryTestStore(t, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), true)

	// When
	_, err := pool.Exec(ctx, `INSERT INTO response_advisories(id,incident_id,agent_id,algorithm_version,action,target,reason,status,requested_by,requested_at,updated_at) VALUES ('shadow','inc-1','agent-1','v3-shadow','increase_monitoring','agent-1','shadow','pending_verification','user:7',$1,$1)`, now)

	// Then
	if err == nil {
		t.Fatal("database accepted v3-shadow advisory")
	}
}

func TestPostgresSchema_rejects_unsupported_host_action(t *testing.T) {
	// Given
	_, pool, ctx, now := newAdvisoryTestStore(t, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC), true)

	// When
	_, err := pool.Exec(ctx, `INSERT INTO response_advisories(id,incident_id,agent_id,algorithm_version,action,target,reason,status,requested_by,requested_at,updated_at) VALUES ('host-action','inc-1','agent-1','v2-active','process_kill','agent-1','unsupported','pending_verification','user:7',$1,$1)`, now)

	// Then
	if err == nil {
		t.Fatal("database accepted unsupported host action")
	}
}
