package controlaudit

import (
	"crypto/ed25519"
	"errors"
	"time"
)

var (
	ErrIntegrity        = errors.New("controlaudit: integrity verification failed")
	ErrQueryForbidden   = errors.New("controlaudit: query forbidden")
	ErrWriteInterrupted = errors.New("controlaudit: anchor write interrupted")
)

const DefaultAnchorDir = "/var/lib/lyflow/audit-anchors"

type QueryRole string

const (
	QueryViewer  QueryRole = "viewer"
	QueryAuditor QueryRole = "auditor"
	QueryAdmin   QueryRole = "admin"
)

type HealthCode string

const HealthIntegrityFailure HealthCode = "audit_integrity_failure"

type HealthAlert struct {
	Code HealthCode
	At   time.Time
}

type Entry struct {
	Actor    string                 `json:"actor"`
	Action   string                 `json:"action"`
	Resource string                 `json:"resource"`
	Result   string                 `json:"result"`
	Fields   map[string]interface{} `json:"fields,omitempty"`
}

type Record struct {
	Sequence     uint64                 `json:"sequence"`
	Actor        string                 `json:"actor"`
	Action       string                 `json:"action"`
	Resource     string                 `json:"resource"`
	Result       string                 `json:"result"`
	Fields       map[string]interface{} `json:"fields,omitempty"`
	OccurredAt   time.Time              `json:"occurred_at"`
	PreviousHash string                 `json:"previous_hash"`
	Hash         string                 `json:"hash"`
}

type Batch struct {
	ID                string   `json:"id"`
	Records           []Record `json:"records"`
	PreviousBatchHash string   `json:"previous_batch_hash"`
	Hash              string   `json:"hash"`
	CanonicalJSON     []byte   `json:"-"`
}

type Config struct {
	Dir       string
	Signer    ed25519.PrivateKey
	Sign      func([]byte) []byte
	PublicKey ed25519.PublicKey
	Now       func() time.Time
	Health    func(HealthAlert)
}

type anchor struct {
	BatchID            string    `json:"batch_id"`
	BatchHash          string    `json:"batch_hash"`
	PreviousAnchorHash string    `json:"previous_anchor_hash"`
	CreatedAt          time.Time `json:"created_at"`
	Signature          string    `json:"signature"`
}

type retentionCheckpoint struct {
	LastPrunedAnchorHash string `json:"last_pruned_anchor_hash"`
	LastPrunedBatchHash  string `json:"last_pruned_batch_hash"`
	LastPrunedBatchID    string `json:"last_pruned_batch_id"`
	Signature            string `json:"signature"`
}
