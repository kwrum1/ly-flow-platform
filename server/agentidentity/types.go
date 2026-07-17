package agentidentity

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrCredentialRejected = errors.New("agent identity: credential rejected")
	ErrInvalidAgentID     = errors.New("agent identity: invalid agent id")
	ErrInvalidCredential  = errors.New("agent identity: invalid credential")
	ErrInvalidTransition  = errors.New("agent identity: invalid transition")
	ErrOverlapTooLong     = errors.New("agent identity: overlap exceeds 24 hours")
	ErrStaleVersion       = errors.New("agent identity: stale version")
	ErrTerminalState      = errors.New("agent identity: terminal state")
	ErrTokenExpired       = errors.New("agent identity: token expired")
	ErrTokenUsed          = errors.New("agent identity: token already used")
	ErrTokenUnknown       = errors.New("agent identity: token unknown")
)

type State string

const (
	StateBridgeRelease   State = "bridge_release"
	StateLegacyVerified  State = "legacy_verified"
	StateHashMigrated    State = "hash_migrated"
	StateOverlapRotation State = "overlap_rotation"
	StateConfirmed       State = "confirmed"
	StateLegacyRetired   State = "legacy_retired"
	StateRevoked         State = "revoked"
)

type Transport string

const (
	TransportHTTP Transport = "http"
	TransportGRPC Transport = "grpc"
)

type EnabledTransports struct {
	HTTP bool
	GRPC bool
}

func (e EnabledTransports) enabled(transport Transport) bool {
	switch transport {
	case TransportHTTP:
		return e.HTTP
	case TransportGRPC:
		return e.GRPC
	default:
		return false
	}
}

func (e EnabledTransports) allConfirmed(confirmed map[Transport]bool) bool {
	return (!e.HTTP || confirmed[TransportHTTP]) && (!e.GRPC || confirmed[TransportGRPC])
}

type AgentID struct{ value string }

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func NewAgentID(raw string) (AgentID, error) {
	if !agentIDPattern.MatchString(raw) {
		return AgentID{}, fmt.Errorf("%q: %w", raw, ErrInvalidAgentID)
	}
	return AgentID{value: raw}, nil
}

func (id AgentID) String() string { return id.value }

func ParseState(raw string) (State, error) {
	state := State(raw)
	switch state {
	case StateBridgeRelease, StateLegacyVerified, StateHashMigrated, StateOverlapRotation, StateConfirmed, StateLegacyRetired, StateRevoked:
		return state, nil
	default:
		return "", fmt.Errorf("state %q: %w", raw, ErrInvalidTransition)
	}
}
