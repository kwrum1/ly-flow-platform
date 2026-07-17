package advisoryresponse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const ActiveAlgorithm = "v2-active"

var (
	ErrActiveInputRequired  = errors.New("advisory response requires v2-active input")
	ErrAgentUnhealthy       = errors.New("Agent is unhealthy")
	ErrConflict             = errors.New("advisory response idempotency conflict")
	ErrForbidden            = errors.New("advisory response action forbidden")
	ErrInvalidCandidate     = errors.New("invalid advisory candidate")
	ErrNotFound             = errors.New("advisory response not found")
	ErrStaleIncident        = errors.New("incident is stale")
	ErrTwoPersonRequired    = errors.New("two-person approval required")
	ErrUnsupportedAction    = errors.New("unsupported advisory action")
	ErrVerificationFailed   = errors.New("advisory verification failed")
	ErrVerificationRequired = errors.New("advisory verification required")
)

type Action string

const (
	ActionAnalystReview         Action = "analyst_review"
	ActionIncreaseMonitoring    Action = "increase_monitoring"
	ActionCollectForensicBundle Action = "collect_forensic_bundle"
	ActionSuggestProxyACL       Action = "suggest_waf_or_proxy_acl"
	ActionSuggestHostIsolation  Action = "suggest_host_isolation"
)

func SupportedAction(action Action) bool {
	switch action {
	case ActionAnalystReview, ActionIncreaseMonitoring, ActionCollectForensicBundle, ActionSuggestProxyACL, ActionSuggestHostIsolation:
		return true
	default:
		return false
	}
}

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleAnalyst  Role = "analyst"
	RoleVerifier Role = "verifier"
)

type Actor struct {
	ID   string `json:"id"`
	Role Role   `json:"role"`
}

type CandidateInput struct {
	ID         string
	IncidentID string
	AgentID    string
	Algorithm  string
	Action     Action
	Target     string
	Reason     string
}

type Candidate struct {
	id         string
	incidentID string
	agentID    string
	action     Action
	target     string
	reason     string
}

func NewCandidate(input CandidateInput) (Candidate, error) {
	if input.Algorithm != ActiveAlgorithm {
		return Candidate{}, fmt.Errorf("algorithm %q: %w", input.Algorithm, ErrActiveInputRequired)
	}
	if !SupportedAction(input.Action) {
		return Candidate{}, fmt.Errorf("action %q: %w", input.Action, ErrUnsupportedAction)
	}
	if strings.TrimSpace(input.ID) == "" || strings.TrimSpace(input.IncidentID) == "" || strings.TrimSpace(input.AgentID) == "" || strings.TrimSpace(input.Target) == "" || strings.TrimSpace(input.Reason) == "" {
		return Candidate{}, ErrInvalidCandidate
	}
	if input.ID != CandidateID(input.IncidentID, input.Action, input.Target) {
		return Candidate{}, ErrInvalidCandidate
	}
	return Candidate{
		id: strings.TrimSpace(input.ID), incidentID: strings.TrimSpace(input.IncidentID),
		agentID: strings.TrimSpace(input.AgentID), action: input.Action,
		target: strings.TrimSpace(input.Target), reason: strings.TrimSpace(input.Reason),
	}, nil
}

func (candidate Candidate) ID() string { return candidate.id }

func CandidateID(incidentID string, action Action, target string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{strings.TrimSpace(incidentID), string(action), strings.TrimSpace(target)}, "\x00")))
	return hex.EncodeToString(digest[:])
}

type Status string

const (
	StatusPendingVerification Status = "pending_verification"
	StatusPendingApproval     Status = "pending_approval"
	StatusApproved            Status = "approved"
)

type Verification struct {
	Adapter    string    `json:"adapter"`
	Applied    bool      `json:"applied"`
	RolledBack bool      `json:"rolled_back"`
	VerifiedAt time.Time `json:"verified_at"`
}

type SimulationAdapter interface {
	Simulate(context.Context, Candidate) (Verification, error)
}

type SubmitCommand struct {
	Candidate      Candidate
	Actor          Actor
	IdempotencyKey string
}

type VerifyCommand struct {
	AdvisoryID     string
	Actor          Actor
	IdempotencyKey string
	Adapter        SimulationAdapter
}

type ApprovalCommand struct {
	AdvisoryID     string
	Actor          Actor
	IdempotencyKey string
}

type Advisory struct {
	ID           string        `json:"id"`
	IncidentID   string        `json:"incident_id"`
	AgentID      string        `json:"agent_id"`
	Algorithm    string        `json:"algorithm"`
	Action       Action        `json:"action"`
	Target       string        `json:"target"`
	Reason       string        `json:"reason"`
	Status       Status        `json:"status"`
	RequestedBy  string        `json:"requested_by"`
	ApprovedBy   string        `json:"approved_by,omitempty"`
	Verification *Verification `json:"verification,omitempty"`
	RequestedAt  time.Time     `json:"requested_at"`
	ApprovedAt   *time.Time    `json:"approved_at,omitempty"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type Limits struct {
	IncidentMaxAge time.Duration
	AgentMaxAge    time.Duration
}

func DefaultLimits() Limits {
	return Limits{IncidentMaxAge: 30 * time.Minute, AgentMaxAge: 5 * time.Minute}
}
