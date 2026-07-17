package agentpolicy

import (
	"context"
	"time"
)

type State string

const (
	StateDraft      State = "draft"
	StateCanary     State = "canary"
	StateActive     State = "active"
	StateSuperseded State = "superseded"
	StateExpired    State = "expired"
	StateRolledBack State = "rolled_back"
)

type ReplayMetrics struct {
	SampleCount       int     `json:"sample_count"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
}

type CanaryObservation struct {
	Succeeded     bool           `json:"succeeded"`
	FailureReason string         `json:"failure_reason,omitempty"`
	Replay        *ReplayMetrics `json:"replay,omitempty"`
}

type PersistedPolicy struct {
	Envelope  SignedPolicy       `json:"envelope"`
	State     State              `json:"state"`
	Canary    *CanaryObservation `json:"canary,omitempty"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

type Assignment struct {
	AgentID      string       `json:"agent_id"`
	Envelope     SignedPolicy `json:"envelope"`
	AssignedAt   time.Time    `json:"assigned_at"`
	ACKVersion   uint64       `json:"ack_version,omitempty"`
	ACKSignature string       `json:"ack_signature,omitempty"`
	ACKedAt      time.Time    `json:"acked_at,omitempty"`
}

type Acknowledgement struct {
	AgentID   string
	Version   uint64
	Signature string
}

type RuntimeCapabilities struct {
	Languages []Language
}

type AssignmentTarget struct {
	AgentID      string
	Capabilities RuntimeCapabilities
}

type PolicyUpdate struct {
	Policy   PersistedPolicy
	Expected State
	Event    AuditEvent
}

type RollbackChange struct {
	Current PersistedPolicy
	Target  PersistedPolicy
	Event   AuditEvent
}

type AuditEvent struct {
	Version    uint64    `json:"version"`
	Type       string    `json:"type"`
	AuditLink  string    `json:"audit_link"`
	Detail     string    `json:"detail,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type Store interface {
	Create(context.Context, PersistedPolicy, AuditEvent) error
	Get(context.Context, uint64) (PersistedPolicy, error)
	Latest(context.Context) (PersistedPolicy, error)
	Active(context.Context) (PersistedPolicy, error)
	Update(context.Context, PolicyUpdate) error
	Promote(context.Context, PersistedPolicy, AuditEvent) error
	Rollback(context.Context, RollbackChange) error
	Assign(context.Context, Assignment, AuditEvent) error
	Assignment(context.Context, string) (Assignment, error)
	Acknowledge(context.Context, Assignment, AuditEvent) error
	ACKCount(context.Context, uint64) (int, error)
}
