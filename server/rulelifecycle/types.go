package rulelifecycle

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

var (
	ErrURLPolicy         = errors.New("rulelifecycle: source URL policy rejected")
	ErrAddressPolicy     = errors.New("rulelifecycle: source address policy rejected")
	ErrDigestMismatch    = errors.New("rulelifecycle: source digest mismatch")
	ErrSizeLimit         = errors.New("rulelifecycle: source size limit exceeded")
	ErrTimeout           = errors.New("rulelifecycle: source fetch timed out")
	ErrCompile           = errors.New("rulelifecycle: strict compile failed")
	ErrForbidden         = errors.New("rulelifecycle: operation forbidden")
	ErrAudit             = errors.New("rulelifecycle: durable audit unavailable")
	ErrHealth            = errors.New("rulelifecycle: runtime health check failed")
	ErrManifestSignature = errors.New("rulelifecycle: manifest signature invalid")
	ErrRevision          = errors.New("rulelifecycle: invalid revision")
)

const (
	AuditResultSucceeded = "succeeded"
	AuditResultFailed    = "failed"
	AuditResultDenied    = "denied"
	activeManifestName   = "active-manifest.json"
)

type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

type FetchPolicy struct {
	AllowedSchemes []string
	AllowedDomains []string
	MaxBytes       int64
	Timeout        time.Duration
	MaxRedirects   int
}

type SourcePin struct {
	URL      string `json:"url"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
}

type FetchedSource struct {
	Pin       SourcePin
	FinalURL  string
	Content   []byte
	Redirects int
	verified  bool
}

type LocalSource struct {
	SourceID string
	Revision string
	SHA256   string
	Content  []byte
}

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

type Actor struct {
	ID   string
	Role Role
}

type AuditEvent struct {
	Actor    string
	Action   string
	Resource string
	Result   string
	Fields   map[string]interface{}
}

type Audit interface {
	Record(ctx context.Context, event AuditEvent) error
}

type Runtime interface {
	Snapshot(ctx context.Context) (RuntimeState, error)
	Reload(ctx context.Context, manifestPath, digest string) error
	Restore(ctx context.Context, state RuntimeState) error
	Health(ctx context.Context, revision, digest string) error
}

type RuntimeState struct {
	ManifestPath string `json:"manifest_path"`
	Revision     string `json:"revision"`
	Digest       string `json:"digest"`
}

type Preview struct {
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
	RuleCount     int    `json:"rule_count"`
	WouldActivate bool   `json:"would_activate"`
}

type ActiveManifest struct {
	SchemaVersion     string    `json:"schema_version"`
	Revision          string    `json:"revision"`
	Digest            string    `json:"digest"`
	BundlePath        string    `json:"bundle_path"`
	SourceURL         string    `json:"source_url"`
	SourceRevision    string    `json:"source_revision"`
	ActivatedAt       time.Time `json:"activated_at"`
	PreviousRevision  string    `json:"previous_revision,omitempty"`
	SignerFingerprint string    `json:"signer_fingerprint"`
	Signature         string    `json:"signature"`
}

type ManagerConfig struct {
	RootDir  string
	Signer   trustroot.Signer
	Verifier trustroot.Layout
	Audit    Audit
	Runtime  Runtime
	Fetcher  *Fetcher
	Now      func() time.Time
}
