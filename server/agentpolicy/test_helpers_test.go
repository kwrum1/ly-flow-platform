package agentpolicy

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

type policyHarness struct {
	manager *Manager
	store   *MemoryStore
	now     time.Time
}

func newPolicyHarness(t *testing.T) *policyHarness {
	t.Helper()
	return newPolicyHarnessWithBlockOptInFlag(t, false)
}

func newPolicyHarnessWithBlockOptIn(t *testing.T) *policyHarness {
	t.Helper()
	return newPolicyHarnessWithBlockOptInFlag(t, true)
}

func newPolicyHarnessWithBlockOptInFlag(t *testing.T, allowProductionBlock bool) *policyHarness {
	t.Helper()
	base := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap trust root: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.PolicySigner)
	if err != nil {
		t.Fatalf("load policy signer: %v", err)
	}
	harness := &policyHarness{store: NewMemoryStore(), now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	harness.manager = NewManager(ManagerConfig{
		Store: harness.store, Signer: signer, Verifier: layout,
		Now: func() time.Time { return harness.now }, AllowProductionBlock: allowProductionBlock,
	})
	if _, err := harness.manager.EnsureDefault(context.Background(), "platform-owner", "audit://policy/default"); err != nil {
		t.Fatalf("ensure default policy: %v", err)
	}
	return harness
}

func (harness *policyHarness) monitorPolicy(version uint64) Policy {
	return Policy{
		ID: "rasp-primary", Version: version, Owner: "security-owner", Mode: ModeMonitor,
		Selectors: Selectors{AgentIDs: []string{"agent-canary"}, Languages: []shared.Language{shared.LanguagePython}},
		ExpiresAt: harness.now.Add(time.Hour), FailBehavior: FailMonitor,
		Limits:    Limits{MaxEventsPerSecond: 100, MaxBlocksPerMinute: 0, ReplayMinSamples: 1000, ReplayMaxFalsePositiveRate: 0.01},
		Canary:    CanaryPolicy{RequiredACKs: 1},
		Rollback:  RollbackPolicy{TargetVersion: 1, Deadline: harness.now.Add(2 * time.Hour)},
		AuditLink: "audit://policy/rasp-primary",
	}
}

func (harness *policyHarness) blockPolicy(version uint64) Policy {
	policy := harness.monitorPolicy(version)
	policy.Mode = ModeBlock
	policy.Limits.MaxBlocksPerMinute = 5
	return policy
}

func successfulCanary() CanaryObservation {
	return CanaryObservation{Succeeded: true, Replay: &ReplayMetrics{SampleCount: 2000, FalsePositiveRate: 0.001}}
}

func createCanaryForTest(t *testing.T, harness *policyHarness, policy Policy) {
	t.Helper()
	ctx := context.Background()
	if _, err := harness.manager.Create(ctx, policy); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := harness.manager.StartCanary(ctx, policy.Version); err != nil {
		t.Fatalf("start canary: %v", err)
	}
}

func ackCanaryForTest(t *testing.T, harness *policyHarness, version uint64) {
	t.Helper()
	ctx := context.Background()
	assignment, err := harness.manager.Assign(ctx, assignmentTarget("agent-canary", shared.LanguagePython), version)
	if err != nil {
		t.Fatalf("assign policy: %v", err)
	}
	if err := harness.manager.Acknowledge(ctx, Acknowledgement{AgentID: assignment.AgentID, Version: version, Signature: assignment.Envelope.Signature}); err != nil {
		t.Fatalf("acknowledge policy: %v", err)
	}
}

func assignmentTarget(agentID string, languages ...shared.Language) AssignmentTarget {
	return AssignmentTarget{AgentID: agentID, Capabilities: RuntimeCapabilities{Languages: languages}}
}

func completeCanaryForTest(t *testing.T, harness *policyHarness, version uint64, observation CanaryObservation) {
	t.Helper()
	if err := harness.manager.CompleteCanary(context.Background(), version, observation); err != nil {
		t.Fatalf("complete canary: %v", err)
	}
}
