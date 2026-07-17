package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	ErrBootstrapTTLInvalid        = errors.New("bootstrap ttl invalid")
	ErrBootstrapTokenInvalid      = errors.New("bootstrap token invalid")
	ErrBootstrapTokenExpired      = errors.New("bootstrap token expired")
	ErrBootstrapTokenUsed         = errors.New("bootstrap token used")
	ErrBootstrapRecoveryState     = errors.New("bootstrap recovery state mismatch")
	ErrBootstrapOutputUnavailable = errors.New("bootstrap controlling terminal unavailable")
	ErrRegistrationRoleRejected   = errors.New("registration cannot accept caller role")
)

type BootstrapIssueMode string

const (
	BootstrapCreate  BootstrapIssueMode = "create"
	BootstrapRecover BootstrapIssueMode = "recover"
)

type BootstrapConsumeRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type BootstrapAuditEvent struct {
	Action    string
	Recovered bool
	ExpiresAt time.Time
	At        time.Time
}

type BootstrapTokenStore interface {
	CreateBootstrapToken(ctx context.Context, tokenHash [32]byte, expiresAt time.Time, recovered bool) error
	ConsumeBootstrapToken(ctx context.Context, tokenHash [32]byte, now time.Time, username, passwordHash string) error
	BootstrapTokenActive(ctx context.Context, now time.Time) (bool, error)
	RevokeBootstrapToken(ctx context.Context, tokenHash [32]byte, now time.Time) error
}

type BootstrapTokenManager struct {
	store        BootstrapTokenStore
	authService  *Service
	output       io.Writer
	random       io.Reader
	now          func() time.Time
	audit        func(BootstrapAuditEvent)
	hashPassword func(string) (string, error)
}

func NewBootstrapTokenManager(store BootstrapTokenStore, authService *Service, output io.Writer) *BootstrapTokenManager {
	return &BootstrapTokenManager{
		store:        store,
		authService:  authService,
		output:       output,
		random:       rand.Reader,
		now:          time.Now,
		hashPassword: func(password string) (string, error) { return authService.HashPassword(password) },
	}
}

func (m *BootstrapTokenManager) Issue(ctx context.Context, mode BootstrapIssueMode, ttl time.Duration) error {
	if ttl <= 0 || ttl > 15*time.Minute {
		return ErrBootstrapTTLInvalid
	}
	if mode != BootstrapCreate && mode != BootstrapRecover {
		return fmt.Errorf("unknown bootstrap issue mode %q", mode)
	}
	if m.output == nil {
		return ErrBootstrapOutputUnavailable
	}
	secret, tokenHash, err := generateBootstrapSecret(m.random)
	if err != nil {
		return fmt.Errorf("generate bootstrap token: %w", err)
	}
	if err := m.store.CreateBootstrapToken(ctx, tokenHash, m.now().Add(ttl), mode == BootstrapRecover); err != nil {
		return fmt.Errorf("store bootstrap token: %w", err)
	}
	if _, err := io.WriteString(m.output, secret+"\n"); err != nil {
		revokeErr := m.store.RevokeBootstrapToken(ctx, tokenHash, m.now())
		return errors.Join(fmt.Errorf("display bootstrap token: %w", err), revokeErr)
	}
	if m.audit != nil {
		m.audit(BootstrapAuditEvent{Action: string(mode), Recovered: mode == BootstrapRecover, ExpiresAt: m.now().Add(ttl), At: m.now()})
	}
	return nil
}

func (m *BootstrapTokenManager) Active(ctx context.Context) (bool, error) {
	return m.store.BootstrapTokenActive(ctx, m.now())
}

func (m *BootstrapTokenManager) Consume(ctx context.Context, req BootstrapConsumeRequest) error {
	if req.Token == "" || req.Username == "" || req.Password == "" {
		return ErrBootstrapTokenInvalid
	}
	if m.hashPassword == nil {
		return errors.New("missing password hasher")
	}
	tokenHash, err := hashBootstrapSecret(req.Token)
	if err != nil {
		return err
	}
	passwordHash, err := m.hashPassword(req.Password)
	if err != nil {
		return err
	}
	return m.store.ConsumeBootstrapToken(ctx, tokenHash, m.now(), req.Username, passwordHash)
}

func NormalizeRegistrationRole(role string) (UserRole, error) {
	if role == "" {
		return RoleViewer, nil
	}
	return "", ErrRegistrationRoleRejected
}

func generateBootstrapSecret(random io.Reader) (string, [32]byte, error) {
	var raw [32]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	secret := hex.EncodeToString(raw[:])
	return secret, sha256.Sum256(raw[:]), nil
}

func hashBootstrapSecret(secret string) ([32]byte, error) {
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, ErrBootstrapTokenInvalid
	}
	var raw [32]byte
	copy(raw[:], decoded)
	return sha256.Sum256(raw[:]), nil
}

func compareBootstrapHash(left, right [32]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func isLoopbackRemote(remoteAddr string) bool {
	host := remoteAddr
	if parsed, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsed
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
