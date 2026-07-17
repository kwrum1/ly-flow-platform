package auth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryBootstrapStore struct {
	mu           sync.Mutex
	tokenHash    [32]byte
	expiresAt    time.Time
	used         bool
	recovered    bool
	admin        bool
	passwordHash string
}

func (s *memoryBootstrapStore) CreateBootstrapToken(_ context.Context, tokenHash [32]byte, expiresAt time.Time, recovered bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if recovered != s.admin {
		return ErrBootstrapRecoveryState
	}
	s.tokenHash = tokenHash
	s.expiresAt = expiresAt
	s.used = false
	s.recovered = recovered
	return nil
}

func (s *memoryBootstrapStore) ConsumeBootstrapToken(_ context.Context, tokenHash [32]byte, now time.Time, _, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used {
		return ErrBootstrapTokenUsed
	}
	if !s.expiresAt.After(now) {
		return ErrBootstrapTokenExpired
	}
	if !compareBootstrapHash(tokenHash, s.tokenHash) {
		return ErrBootstrapTokenInvalid
	}
	if s.admin != s.recovered {
		return ErrBootstrapRecoveryState
	}
	s.admin = true
	s.passwordHash = passwordHash
	s.used = true
	return nil
}

func (s *memoryBootstrapStore) BootstrapTokenActive(_ context.Context, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.used && s.expiresAt.After(now), nil
}

func (s *memoryBootstrapStore) RevokeBootstrapToken(_ context.Context, tokenHash [32]byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if compareBootstrapHash(tokenHash, s.tokenHash) {
		s.used = true
	}
	return nil
}

func newTestBootstrapManager(store BootstrapTokenStore, output *bytes.Buffer, now time.Time) *BootstrapTokenManager {
	manager := NewBootstrapTokenManager(store, NewService("test-secret", time.Hour), output)
	manager.random = bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32))
	manager.now = func() time.Time { return now }
	return manager
}

func TestBootstrapTokenCreateStoresHashAndDisplays256BitsOnce(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store := &memoryBootstrapStore{}
	var output bytes.Buffer
	manager := newTestBootstrapManager(store, &output, now)

	// When
	err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute)

	// Then
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	secret := strings.TrimSpace(output.String())
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("displayed token is not 256 bits: %q", secret)
	}
	if strings.Count(output.String(), secret) != 1 {
		t.Fatalf("token display count=%d, want 1", strings.Count(output.String(), secret))
	}
	if bytes.Contains(store.tokenHash[:], []byte(secret)) || store.tokenHash == [32]byte{} {
		t.Fatal("store must contain a non-empty hash, never plaintext")
	}
	if !store.expiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expires_at=%s", store.expiresAt)
	}
}

func TestBootstrapTokenIssueRejectsTTLOver15Minutes(t *testing.T) {
	// Given
	manager := newTestBootstrapManager(&memoryBootstrapStore{}, &bytes.Buffer{}, time.Now())

	// When
	err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute+time.Second)

	// Then
	if !errors.Is(err, ErrBootstrapTTLInvalid) {
		t.Fatalf("error=%v, want ErrBootstrapTTLInvalid", err)
	}
}

func TestBootstrapTokenConcurrentConsumptionHasSingleWinner(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store := &memoryBootstrapStore{}
	var output bytes.Buffer
	manager := newTestBootstrapManager(store, &output, now)
	if err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute); err != nil {
		t.Fatalf("issue token: %v", err)
	}
	request := BootstrapConsumeRequest{Token: strings.TrimSpace(output.String()), Username: "admin", Password: "LyFlow/2026"}

	// When
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- manager.Consume(context.Background(), request) }()
	}
	first, second := <-results, <-results

	// Then
	successes := 0
	for _, err := range []error{first, second} {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d, errors=(%v, %v)", successes, first, second)
	}
}

func TestBootstrapTokenRecoveryExpiresWithoutChangingAdmin(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store := &memoryBootstrapStore{admin: true, passwordHash: "old"}
	var output bytes.Buffer
	manager := newTestBootstrapManager(store, &output, now)
	if err := manager.Issue(context.Background(), BootstrapRecover, 15*time.Minute); err != nil {
		t.Fatalf("issue recovery: %v", err)
	}
	manager.now = func() time.Time { return now.Add(15 * time.Minute) }

	// When
	err := manager.Consume(context.Background(), BootstrapConsumeRequest{Token: strings.TrimSpace(output.String()), Username: "admin", Password: "New/LyFlow2026"})

	// Then
	if !errors.Is(err, ErrBootstrapTokenExpired) || store.passwordHash != "old" {
		t.Fatalf("error=%v password_hash=%q", err, store.passwordHash)
	}
}

func TestBootstrapHandlerRequiresLoopbackAndClosesAfterUse(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store := &memoryBootstrapStore{}
	var output bytes.Buffer
	manager := newTestBootstrapManager(store, &output, now)
	if err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute); err != nil {
		t.Fatalf("issue token: %v", err)
	}
	handler := NewBootstrapHandler(manager)
	body := `{"token":"` + strings.TrimSpace(output.String()) + `","username":"admin","password":"LyFlow/2026"}`

	// When
	remoteResponse := serveBootstrapRequest(handler, "192.0.2.10:1234", body)
	localResponse := serveBootstrapRequest(handler, "127.0.0.1:1234", body)
	closedResponse := serveBootstrapRequest(handler, "127.0.0.1:1234", body)

	// Then
	if remoteResponse.Code != http.StatusForbidden || localResponse.Code != http.StatusCreated || closedResponse.Code != http.StatusNotFound {
		t.Fatalf("statuses remote=%d local=%d closed=%d", remoteResponse.Code, localResponse.Code, closedResponse.Code)
	}
}

func serveBootstrapRequest(handler *BootstrapHandler, remoteAddr, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap-token", strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	response := httptest.NewRecorder()
	handler.Consume(response, request)
	return response
}

func TestNormalizeRegistrationRoleRejectsCallerRole(t *testing.T) {
	for _, role := range []string{"admin", "analyst", "viewer", "owner"} {
		if _, err := NormalizeRegistrationRole(role); !errors.Is(err, ErrRegistrationRoleRejected) {
			t.Fatalf("role=%q error=%v, want rejection", role, err)
		}
	}
}
