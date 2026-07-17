package agentidentity

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCredentialAcceptanceTable(t *testing.T) {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		state      State
		credential string
		want       bool
	}{
		{StateBridgeRelease, "legacy", true},
		{StateBridgeRelease, "new", false},
		{StateLegacyVerified, "legacy", true},
		{StateLegacyVerified, "new", false},
		{StateHashMigrated, "legacy", true},
		{StateHashMigrated, "new", false},
		{StateOverlapRotation, "legacy", true},
		{StateOverlapRotation, "new", true},
		{StateConfirmed, "legacy", true},
		{StateConfirmed, "new", true},
		{StateLegacyRetired, "legacy", false},
		{StateLegacyRetired, "new", true},
		{StateRevoked, "legacy", false},
		{StateRevoked, "new", false},
	}
	for _, test := range tests {
		for _, transport := range []Transport{TransportHTTP, TransportGRPC} {
			t.Run(string(transport)+"_"+string(test.state)+"_"+test.credential, func(t *testing.T) {
				// Given
				record := testRecord(t, test.state, now)

				// When
				err := record.Authenticate(test.credential, transport, now)

				// Then
				if (err == nil) != test.want {
					t.Fatalf("Authenticate() error = %v, want accepted %v", err, test.want)
				}
			})
		}
	}
}

func TestTransitionGuardsAndRollback(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	record := testRecord(t, StateBridgeRelease, now)

	// When / Then
	for _, state := range []State{StateLegacyVerified, StateHashMigrated} {
		if err := record.Transition(state, record.Version()); err != nil {
			t.Fatalf("transition to %s: %v", state, err)
		}
	}
	if err := record.Transition(StateConfirmed, record.Version()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("skipped transition error = %v", err)
	}
	if err := record.Rollback(record.Version()); err != nil {
		t.Fatalf("one-step rollback: %v", err)
	}
	if record.State() != StateLegacyVerified {
		t.Fatalf("state after rollback = %s", record.State())
	}
	if err := record.Transition(StateHashMigrated, record.Version()-1); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("stale transition error = %v", err)
	}
}

func TestOverlapIsBoundedAndConfirmationRequiresEveryEnabledTransport(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	record := testRecord(t, StateHashMigrated, now)

	// When / Then
	if err := record.BeginRotation("new", 24*time.Hour+time.Second, now, record.Version()); !errors.Is(err, ErrOverlapTooLong) {
		t.Fatalf("oversized overlap error = %v", err)
	}
	if err := record.BeginRotation("new", 24*time.Hour, now, record.Version()); err != nil {
		t.Fatalf("begin rotation: %v", err)
	}
	if err := record.Authenticate("new", TransportHTTP, now); err != nil {
		t.Fatalf("http new credential: %v", err)
	}
	if record.State() != StateOverlapRotation {
		t.Fatalf("state after one transport = %s", record.State())
	}
	if err := record.Authenticate("new", TransportGRPC, now); err != nil {
		t.Fatalf("grpc new credential: %v", err)
	}
	if record.State() != StateConfirmed {
		t.Fatalf("state after all transports = %s", record.State())
	}
	if err := record.Authenticate("legacy", TransportHTTP, now.Add(25*time.Hour)); err != nil {
		t.Fatalf("confirmed legacy credential before retirement: %v", err)
	}
	if err := record.Rollback(record.Version()); err != nil {
		t.Fatalf("confirmed rollback: %v", err)
	}
	if record.State() != StateOverlapRotation {
		t.Fatalf("state after confirmed rollback = %s", record.State())
	}
}

func TestEnrollmentTokenIsOneTimeExpiringAndBindsImmutableID(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := NewManager(NewMemoryStore(), func() time.Time { return now })
	token, err := manager.IssueEnrollmentToken("agent-fixed", time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// When
	record, err := manager.Enroll(token, "legacy", EnabledTransports{HTTP: true, GRPC: true})

	// Then
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if record.ID().String() != "agent-fixed" {
		t.Fatalf("enrolled id = %q", record.ID().String())
	}
	if _, err := manager.Enroll(token, "other", EnabledTransports{HTTP: true}); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("replayed token error = %v", err)
	}
	expired, err := manager.IssueEnrollmentToken("agent-expired", time.Second)
	if err != nil {
		t.Fatalf("issue expiring token: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := manager.Enroll(expired, "legacy", EnabledTransports{HTTP: true}); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token error = %v", err)
	}
}

func TestRevocationAndRetirementAreTerminalAndRecoveryKeepsID(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := NewManager(NewMemoryStore(), func() time.Time { return now })
	record := testRecord(t, StateConfirmed, now)
	if err := manager.Store(record); err != nil {
		t.Fatalf("store confirmed record: %v", err)
	}

	// When / Then
	if err := manager.RetireLegacy(record.ID(), record.Version()); err != nil {
		t.Fatalf("retire legacy: %v", err)
	}
	if err := manager.Rollback(record.ID(), record.Version()); !errors.Is(err, ErrTerminalState) {
		t.Fatalf("retired rollback error = %v", err)
	}
	token, err := manager.IssueRecoveryToken(record.ID(), time.Minute)
	if err != nil {
		t.Fatalf("issue recovery: %v", err)
	}
	recovered, err := manager.Recover(token, "recovered")
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if recovered.ID() != record.ID() || recovered.State() != StateLegacyRetired {
		t.Fatalf("recovered identity = %s state = %s", recovered.ID().String(), recovered.State())
	}
	if err := recovered.Authenticate("recovered", TransportHTTP, now); err != nil {
		t.Fatalf("recovered credential: %v", err)
	}

	revoked := testRecord(t, StateHashMigrated, now)
	if err := revoked.Revoke(revoked.Version()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := revoked.Rollback(revoked.Version()); !errors.Is(err, ErrTerminalState) {
		t.Fatalf("revoked rollback error = %v", err)
	}
}

func TestConcurrentRotationHasOneWinner(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	record := testRecord(t, StateHashMigrated, now)
	version := record.Version()
	var wait sync.WaitGroup
	results := make(chan error, 2)

	// When
	for _, credential := range []string{"new-a", "new-b"} {
		wait.Add(1)
		go func(value string) {
			defer wait.Done()
			results <- record.BeginRotation(value, time.Hour, now, version)
		}(credential)
	}
	wait.Wait()
	close(results)

	// Then
	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful rotations = %d, want 1", successes)
	}
}

func testRecord(t *testing.T, state State, now time.Time) *Record {
	t.Helper()
	id, err := NewAgentID("agent-fixed")
	if err != nil {
		t.Fatalf("agent id: %v", err)
	}
	record, err := NewLegacyRecord(id, "legacy", EnabledTransports{HTTP: true, GRPC: true})
	if err != nil {
		t.Fatalf("new legacy record: %v", err)
	}
	for record.State() != state {
		switch record.State() {
		case StateBridgeRelease:
			if state == StateRevoked {
				if err := record.Revoke(record.Version()); err != nil {
					t.Fatalf("revoke fixture: %v", err)
				}
				continue
			}
			if err := record.Transition(StateLegacyVerified, record.Version()); err != nil {
				t.Fatalf("legacy verified fixture: %v", err)
			}
		case StateLegacyVerified:
			if err := record.Transition(StateHashMigrated, record.Version()); err != nil {
				t.Fatalf("hash migrated fixture: %v", err)
			}
		case StateHashMigrated:
			if err := record.BeginRotation("new", time.Hour, now, record.Version()); err != nil {
				t.Fatalf("rotation fixture: %v", err)
			}
		case StateOverlapRotation:
			if err := record.Authenticate("new", TransportHTTP, now); err != nil {
				t.Fatalf("http confirmation fixture: %v", err)
			}
			if err := record.Authenticate("new", TransportGRPC, now); err != nil {
				t.Fatalf("grpc confirmation fixture: %v", err)
			}
		case StateConfirmed:
			if err := record.Transition(StateLegacyRetired, record.Version()); err != nil {
				t.Fatalf("retired fixture: %v", err)
			}
		default:
			t.Fatalf("cannot build state %s from %s", state, record.State())
		}
	}
	return record
}
