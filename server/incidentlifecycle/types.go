package incidentlifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const ActiveAlgorithm = "v2-active"

var (
	ErrActiveInputRequired    = errors.New("incident lifecycle requires v2-active input")
	ErrConflict               = errors.New("incident lifecycle version conflict")
	ErrForbidden              = errors.New("incident lifecycle action forbidden")
	ErrIllegalTransition      = errors.New("illegal incident lifecycle transition")
	ErrInvalidCommand         = errors.New("invalid incident lifecycle command")
	ErrLegacySnapshotInvalid  = errors.New("durable legacy incident snapshot invalid")
	ErrLegacySnapshotRequired = errors.New("durable legacy incident snapshot required")
	ErrNotFound               = errors.New("incident not found")
)

type Status string

const (
	StatusOpen       Status = "open"
	StatusTriaged    Status = "triaged"
	StatusProcessing Status = "processing"
	StatusResolved   Status = "resolved"
	StatusClosed     Status = "closed"
)

func (status Status) Valid() bool {
	switch status {
	case StatusOpen, StatusTriaged, StatusProcessing, StatusResolved, StatusClosed:
		return true
	default:
		return false
	}
}

func LegalTransition(from, to Status) bool {
	if from == to {
		return true
	}
	switch from {
	case StatusOpen:
		return to == StatusTriaged || to == StatusProcessing
	case StatusTriaged:
		return to == StatusProcessing
	case StatusProcessing:
		return to == StatusResolved
	case StatusResolved:
		return to == StatusProcessing || to == StatusClosed
	case StatusClosed:
		return false
	default:
		return false
	}
}

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
	RoleSystem  Role = "system"
)

type Actor struct {
	ID   string `json:"id"`
	Role Role   `json:"role"`
}

type Action string

const (
	ActionCreate     Action = "create"
	ActionTransition Action = "transition"
	ActionAssign     Action = "assign"
	ActionSuppress   Action = "suppress"
	ActionSnapshot   Action = "legacy_snapshot"
)

type Evidence struct {
	EventUID      string          `json:"event_uid"`
	SourceNodeUID string          `json:"source_node_uid"`
	Stage         string          `json:"stage"`
	ObservedAt    time.Time       `json:"observed_at"`
	Raw           json.RawMessage `json:"raw,omitempty"`
}

type Candidate struct {
	IncidentID     string
	SourceChainID  string
	CorrelationKey string
	Title          string
	Summary        string
	Severity       string
	FirstSeen      time.Time
	LastSeen       time.Time
	Evidence       []Evidence
}

type ActiveSnapshot struct {
	candidates []Candidate
}

func NewActiveSnapshot(algorithm string, candidates []Candidate) (ActiveSnapshot, error) {
	if algorithm != ActiveAlgorithm {
		return ActiveSnapshot{}, fmt.Errorf("algorithm %q: %w", algorithm, ErrActiveInputRequired)
	}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.IncidentID) == "" || strings.TrimSpace(candidate.SourceChainID) == "" || candidate.FirstSeen.IsZero() || candidate.LastSeen.IsZero() {
			return ActiveSnapshot{}, ErrInvalidCommand
		}
	}
	return ActiveSnapshot{candidates: append([]Candidate(nil), candidates...)}, nil
}

func (snapshot ActiveSnapshot) Candidates() []Candidate {
	return append([]Candidate(nil), snapshot.candidates...)
}

func DedupKey(tenant string, candidate Candidate) string {
	identity := strings.Join([]string{strings.TrimSpace(tenant), ActiveAlgorithm, strings.TrimSpace(candidate.SourceChainID)}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:])
}

type Command struct {
	IncidentID      string
	IdempotencyKey  string
	Actor           Actor
	Action          Action
	To              Status
	Assignee        string
	Reason          string
	SuppressUntil   time.Time
	ExpectedVersion int64
}

type Incident struct {
	ID                string       `json:"id"`
	TenantID          string       `json:"tenant_id"`
	SourceChainID     string       `json:"source_chain_id"`
	Algorithm         string       `json:"algorithm"`
	DedupKey          string       `json:"dedup_key"`
	CorrelationKey    string       `json:"correlation"`
	Title             string       `json:"title"`
	Summary           string       `json:"summary"`
	Severity          string       `json:"severity"`
	Status            Status       `json:"status"`
	Assignee          string       `json:"assignee,omitempty"`
	Suppressed        bool         `json:"suppressed"`
	SuppressedUntil   *time.Time   `json:"suppressed_until,omitempty"`
	SuppressionReason string       `json:"suppression_reason,omitempty"`
	FirstSeen         time.Time    `json:"first_seen"`
	LastSeen          time.Time    `json:"last_seen"`
	AcknowledgeDueAt  time.Time    `json:"acknowledge_due_at"`
	ResolveDueAt      time.Time    `json:"resolve_due_at"`
	AcknowledgedAt    *time.Time   `json:"acknowledged_at,omitempty"`
	ResolvedAt        *time.Time   `json:"resolved_at,omitempty"`
	Version           int64        `json:"version"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
	Evidence          []Evidence   `json:"evidence"`
	Audit             []AuditEvent `json:"audit"`
}

type AuditEvent struct {
	IncidentID     string            `json:"incident_id"`
	ID             int64             `json:"id"`
	IdempotencyKey string            `json:"idempotency_key"`
	PayloadHash    string            `json:"payload_hash"`
	Actor          Actor             `json:"actor"`
	Action         Action            `json:"action"`
	From           Status            `json:"from_status"`
	To             Status            `json:"to_status"`
	Outcome        string            `json:"outcome"`
	Reason         string            `json:"reason,omitempty"`
	Version        int64             `json:"version"`
	OccurredAt     time.Time         `json:"occurred_at"`
	Detail         map[string]string `json:"detail,omitempty"`
}

type SyncReport struct {
	Created       int `json:"created"`
	Updated       int `json:"updated"`
	EvidenceAdded int `json:"evidence_added"`
}

type LegacyStatus struct {
	IncidentID string `json:"incident_id"`
	Status     Status `json:"status"`
}

type SnapshotFieldCounts struct {
	Status            int `json:"status"`
	Assignee          int `json:"assignee"`
	Suppression       int `json:"suppression"`
	Evidence          int `json:"evidence"`
	TransitionHistory int `json:"transition_history"`
}

func (counts SnapshotFieldCounts) Total() int {
	return counts.Status + counts.Assignee + counts.Suppression + counts.Evidence + counts.TransitionHistory
}

type SnapshotReport struct {
	Source               string              `json:"source"`
	SnapshotChecksum     string              `json:"snapshot_checksum"`
	SnapshotCapturedAt   time.Time           `json:"snapshot_captured_at"`
	ImportableFields     []string            `json:"importable_fields"`
	Captured             int                 `json:"captured"`
	Imported             int                 `json:"imported"`
	AlreadyPersisted     int                 `json:"already_persisted"`
	Unmatched            []string            `json:"unmatched"`
	UnrecoverableHistory []string            `json:"unrecoverable_history"`
	Recovered            SnapshotFieldCounts `json:"recovered"`
	Unrecoverable        SnapshotFieldCounts `json:"unrecoverable"`
	UnrecoverableDetails []string            `json:"unrecoverable_details"`
	CutoverMarked        bool                `json:"cutover_marked"`
}
