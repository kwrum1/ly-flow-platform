package ingestionauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentidentity"
)

const (
	AgentIDHeader = "X-Lyflow-Agent-ID"
	MaxBodyBytes  = int64(1 << 20)

	OutcomeAuthenticated    = "authenticated"
	OutcomeAccepted         = "accepted"
	OutcomeRejected         = "rejected"
	OutcomeRateLimited      = "rate_limited"
	OutcomeIdentityMismatch = "identity_mismatch"
	OutcomeClosed           = "closed"
)

var (
	ErrUnauthorized     = errors.New("ingestion auth: valid agent credential required")
	ErrIdentityMismatch = errors.New("ingestion auth: payload identity conflicts with principal")
	ErrRateLimited      = errors.New("ingestion auth: rate limit exceeded")
	ErrBodyTooLarge     = errors.New("ingestion auth: request body too large")
	ErrInvalidJSON      = errors.New("ingestion auth: invalid JSON")
	ErrAuditUnavailable = errors.New("ingestion auth: lifecycle audit unavailable")
)

type Principal struct{ id agentidentity.AgentID }

func (p Principal) AgentID() string { return p.id.String() }

func (p Principal) BindPayloadAgentID(payloadID string) (string, error) {
	payloadID = strings.TrimSpace(payloadID)
	if payloadID != "" && payloadID != p.AgentID() {
		return "", ErrIdentityMismatch
	}
	return p.AgentID(), nil
}

type Event struct {
	AgentID string
	Surface string
	Outcome string
	Reason  string
	At      time.Time
}

type Audit interface {
	Record(context.Context, Event) error
}

type AuditFunc func(context.Context, Event) error

func (f AuditFunc) Record(ctx context.Context, event Event) error { return f(ctx, event) }

type MemoryAudit struct {
	mu     sync.Mutex
	events []Event
}

func NewMemoryAudit() *MemoryAudit { return &MemoryAudit{} }

func (a *MemoryAudit) Record(_ context.Context, event Event) error {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
	return nil
}

func (a *MemoryAudit) Events() []Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Event(nil), a.events...)
}

type Authenticator struct {
	identities *agentidentity.Manager
	audit      Audit
	now        func() time.Time
	limiter    *fixedWindowLimiter
}

func New(identities *agentidentity.Manager, audit Audit, now func() time.Time, limit int, window time.Duration) *Authenticator {
	if now == nil {
		now = time.Now
	}
	if limit <= 0 {
		limit = 120
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Authenticator{identities: identities, audit: audit, now: now, limiter: newFixedWindowLimiter(limit, window)}
}

func (a *Authenticator) HTTPPrincipal(request *http.Request, surface string) (Principal, error) {
	agentID := strings.TrimSpace(request.Header.Get(AgentIDHeader))
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	if !strings.HasPrefix(authorization, "Bearer ") {
		return Principal{}, errors.Join(ErrUnauthorized, a.record(request.Context(), agentID, surface, OutcomeRejected, ErrUnauthorized.Error()))
	}
	credential := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	return a.Authenticate(request.Context(), agentID, credential, agentidentity.TransportHTTP, surface)
}

func (a *Authenticator) Authenticate(ctx context.Context, agentID, credential string, transport agentidentity.Transport, surface string) (Principal, error) {
	id, err := agentidentity.NewAgentID(strings.TrimSpace(agentID))
	if err != nil || strings.TrimSpace(credential) == "" || a == nil || a.identities == nil {
		if a != nil {
			return Principal{}, errors.Join(ErrUnauthorized, a.record(ctx, agentID, surface, OutcomeRejected, ErrUnauthorized.Error()))
		}
		return Principal{}, ErrUnauthorized
	}
	if err := a.identities.Authenticate(id.String(), credential, transport); err != nil {
		return Principal{}, errors.Join(ErrUnauthorized, a.record(ctx, id.String(), surface, OutcomeRejected, ErrUnauthorized.Error()))
	}
	if !a.limiter.Allow(id.String()+"\x00"+surface, a.now()) {
		return Principal{}, errors.Join(ErrRateLimited, a.record(ctx, id.String(), surface, OutcomeRateLimited, ErrRateLimited.Error()))
	}
	if err := a.record(ctx, id.String(), surface, OutcomeAuthenticated, ""); err != nil {
		return Principal{}, err
	}
	return Principal{id: id}, nil
}

func (a *Authenticator) Record(ctx context.Context, principal Principal, surface, outcome, reason string) error {
	return a.record(ctx, principal.AgentID(), surface, outcome, reason)
}

func (a *Authenticator) RecordIdentityMismatch(ctx context.Context, principal Principal, surface string) error {
	return a.record(ctx, principal.AgentID(), surface, OutcomeIdentityMismatch, ErrIdentityMismatch.Error())
}

func (a *Authenticator) record(ctx context.Context, agentID, surface, outcome, reason string) error {
	if a == nil || a.audit == nil {
		return ErrAuditUnavailable
	}
	if err := a.audit.Record(ctx, Event{AgentID: agentID, Surface: surface, Outcome: outcome, Reason: reason, At: a.now().UTC()}); err != nil {
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

func DecodeJSON(writer http.ResponseWriter, request *http.Request, destination interface{}) error {
	request.Body = http.MaxBytesReader(writer, request.Body, MaxBodyBytes)
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return ErrBodyTooLarge
		}
		return fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidJSON
	}
	return nil
}

func IsUnauthorized(err error) bool     { return errors.Is(err, ErrUnauthorized) }
func IsRateLimited(err error) bool      { return errors.Is(err, ErrRateLimited) }
func IsBodyTooLarge(err error) bool     { return errors.Is(err, ErrBodyTooLarge) }
func IsAuditUnavailable(err error) bool { return errors.Is(err, ErrAuditUnavailable) }

type fixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]windowBucket
}

type windowBucket struct {
	start time.Time
	count int
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{limit: limit, window: window, buckets: make(map[string]windowBucket)}
}

func (l *fixedWindowLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket := l.buckets[key]
	if bucket.start.IsZero() || now.Sub(bucket.start) >= l.window {
		l.buckets[key] = windowBucket{start: now, count: 1}
		return true
	}
	if bucket.count >= l.limit {
		return false
	}
	bucket.count++
	l.buckets[key] = bucket
	return true
}
