package agentidentity

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"
)

const maximumOverlap = 24 * time.Hour

type Record struct {
	mu           sync.Mutex
	id           AgentID
	state        State
	legacyHash   [sha256.Size]byte
	newHash      [sha256.Size]byte
	overlapUntil time.Time
	enabled      EnabledTransports
	confirmed    map[Transport]bool
	version      uint64
}

type recordSnapshot struct {
	ID            AgentID
	State         State
	LegacyHash    [sha256.Size]byte
	NewHash       [sha256.Size]byte
	OverlapUntil  time.Time
	Enabled       EnabledTransports
	HTTPConfirmed bool
	GRPCConfirmed bool
	Version       uint64
}

func NewLegacyRecord(id AgentID, credential string, enabled EnabledTransports) (*Record, error) {
	if credential == "" {
		return nil, ErrInvalidCredential
	}
	return &Record{
		id:         id,
		state:      StateBridgeRelease,
		legacyHash: sha256.Sum256([]byte(credential)),
		enabled:    enabled,
		confirmed:  make(map[Transport]bool, 2),
		version:    1,
	}, nil
}

func recordFromSnapshot(snapshot recordSnapshot) *Record {
	return &Record{
		id:           snapshot.ID,
		state:        snapshot.State,
		legacyHash:   snapshot.LegacyHash,
		newHash:      snapshot.NewHash,
		overlapUntil: snapshot.OverlapUntil,
		enabled:      snapshot.Enabled,
		confirmed: map[Transport]bool{
			TransportHTTP: snapshot.HTTPConfirmed,
			TransportGRPC: snapshot.GRPCConfirmed,
		},
		version: snapshot.Version,
	}
}

func (r *Record) snapshot() recordSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return recordSnapshot{
		ID:            r.id,
		State:         r.state,
		LegacyHash:    r.legacyHash,
		NewHash:       r.newHash,
		OverlapUntil:  r.overlapUntil,
		Enabled:       r.enabled,
		HTTPConfirmed: r.confirmed[TransportHTTP],
		GRPCConfirmed: r.confirmed[TransportGRPC],
		Version:       r.version,
	}
}

func (r *Record) ID() AgentID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.id
}

func (r *Record) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *Record) Version() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.version
}

func (r *Record) Authenticate(credential string, transport Transport, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if credential == "" || !r.enabled.enabled(transport) {
		return ErrCredentialRejected
	}
	legacyMatches := secretHashMatches(r.legacyHash, credential)
	newMatches := secretHashMatches(r.newHash, credential)
	switch r.state {
	case StateBridgeRelease, StateLegacyVerified, StateHashMigrated:
		if legacyMatches {
			return nil
		}
	case StateOverlapRotation:
		if now.After(r.overlapUntil) {
			return ErrCredentialRejected
		}
		if legacyMatches {
			return nil
		}
		if newMatches {
			if !r.confirmed[transport] {
				r.confirmed[transport] = true
				r.version++
			}
			if r.enabled.allConfirmed(r.confirmed) {
				r.state = StateConfirmed
			}
			return nil
		}
	case StateConfirmed:
		if legacyMatches || newMatches {
			return nil
		}
	case StateLegacyRetired:
		if newMatches {
			return nil
		}
	case StateRevoked:
		return ErrCredentialRejected
	default:
		return fmt.Errorf("state %q: %w", r.state, ErrInvalidTransition)
	}
	return ErrCredentialRejected
}

func (r *Record) Transition(next State, expectedVersion uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.guardVersion(expectedVersion); err != nil {
		return err
	}
	if r.state == StateLegacyRetired || r.state == StateRevoked {
		return ErrTerminalState
	}
	valid := (r.state == StateBridgeRelease && next == StateLegacyVerified) ||
		(r.state == StateLegacyVerified && next == StateHashMigrated) ||
		(r.state == StateConfirmed && next == StateLegacyRetired)
	if !valid {
		return fmt.Errorf("%s -> %s: %w", r.state, next, ErrInvalidTransition)
	}
	r.state = next
	r.version++
	return nil
}

func (r *Record) BeginRotation(credential string, overlap time.Duration, now time.Time, expectedVersion uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.guardVersion(expectedVersion); err != nil {
		return err
	}
	if r.state != StateHashMigrated {
		return fmt.Errorf("state %s: %w", r.state, ErrInvalidTransition)
	}
	if credential == "" {
		return ErrInvalidCredential
	}
	if overlap <= 0 || overlap > maximumOverlap {
		return ErrOverlapTooLong
	}
	r.newHash = sha256.Sum256([]byte(credential))
	r.overlapUntil = now.Add(overlap)
	r.confirmed = make(map[Transport]bool, 2)
	r.state = StateOverlapRotation
	r.version++
	return nil
}

func (r *Record) Rollback(expectedVersion uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.guardVersion(expectedVersion); err != nil {
		return err
	}
	if r.state == StateLegacyRetired || r.state == StateRevoked {
		return ErrTerminalState
	}
	previous := map[State]State{
		StateLegacyVerified:  StateBridgeRelease,
		StateHashMigrated:    StateLegacyVerified,
		StateOverlapRotation: StateHashMigrated,
		StateConfirmed:       StateOverlapRotation,
	}[r.state]
	if previous == "" {
		return ErrInvalidTransition
	}
	if r.state == StateOverlapRotation {
		r.newHash = [sha256.Size]byte{}
		r.overlapUntil = time.Time{}
		r.confirmed = make(map[Transport]bool, 2)
	}
	r.state = previous
	r.version++
	return nil
}

func (r *Record) Revoke(expectedVersion uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.guardVersion(expectedVersion); err != nil {
		return err
	}
	if r.state == StateLegacyRetired || r.state == StateRevoked {
		return ErrTerminalState
	}
	r.state = StateRevoked
	r.version++
	return nil
}

func (r *Record) recover(credential string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != StateLegacyRetired {
		return ErrInvalidTransition
	}
	if credential == "" {
		return ErrInvalidCredential
	}
	r.newHash = sha256.Sum256([]byte(credential))
	r.version++
	return nil
}

func (r *Record) guardVersion(expected uint64) error {
	if expected != r.version {
		return ErrStaleVersion
	}
	return nil
}

func secretHashMatches(hash [sha256.Size]byte, credential string) bool {
	if hash == [sha256.Size]byte{} || credential == "" {
		return false
	}
	candidate := sha256.Sum256([]byte(credential))
	return subtle.ConstantTimeCompare(hash[:], candidate[:]) == 1
}
