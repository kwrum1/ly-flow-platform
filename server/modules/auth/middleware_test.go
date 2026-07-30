package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuthenticateRejectsInvalidTokenWithJSON(t *testing.T) {
	middleware := NewMiddleware(NewService("test-secret", time.Hour), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-token")
	rec := httptest.NewRecorder()

	middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("content-type=%q", rec.Header().Get("Content-Type"))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "invalid_token" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestAuthenticateRejectsMissingAuthorizationWithJSON(t *testing.T) {
	middleware := NewMiddleware(NewService("test-secret", time.Hour), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "missing_authorization" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestRequireRoleWithoutUserReturnsJSON(t *testing.T) {
	middleware := NewMiddleware(NewService("test-secret", time.Hour), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	middleware.RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "unauthorized" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestRequireRoleRejectsViewerWithForbidden(t *testing.T) {
	middleware := NewMiddleware(NewService("test-secret", time.Hour), nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	ctx := context.WithValue(req.Context(), UserContextKey, int64(42))
	req = req.WithContext(context.WithValue(ctx, RoleContextKey, RoleViewer))
	rec := httptest.NewRecorder()

	middleware.RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
}

func TestAuthenticateEnforcesCurrentUserState(t *testing.T) {
	const token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tests := []struct {
		name       string
		path       string
		user       *User
		wantStatus int
		wantCalls  int
	}{
		{name: "active admin reads system time", path: "/api/v1/system/time", user: &User{ID: 1, Role: RoleAdmin, IsActive: true}, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "active admin reads mirror configuration", path: "/api/v1/traffic/mirror-interface", user: &User{ID: 1, Role: RoleAdmin, IsActive: true}, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "inactive user session is rejected", path: "/api/v1/system/time", user: &User{ID: 1, Role: RoleAdmin}, wantStatus: http.StatusUnauthorized},
		{name: "password change is required for system time", path: "/api/v1/system/time", user: &User{ID: 1, Role: RoleAdmin, IsActive: true, MustChangePassword: true}, wantStatus: http.StatusPreconditionRequired},
		{name: "password change route remains available", path: "/api/v1/auth/change-password", user: &User{ID: 1, Role: RoleAdmin, IsActive: true, MustChangePassword: true}, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "profile route remains available", path: "/api/v1/auth/profile", user: &User{ID: 1, Role: RoleAdmin, IsActive: true, MustChangePassword: true}, wantStatus: http.StatusNoContent, wantCalls: 1},
		{name: "logout route remains available", path: "/api/v1/auth/logout", user: &User{ID: 1, Role: RoleAdmin, IsActive: true, MustChangePassword: true}, wantStatus: http.StatusNoContent, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			middleware := NewMiddleware(
				NewService("test-secret", time.Hour),
				&middlewareTestUserStore{user: test.user},
				middlewareTestSessionReader{session: &Session{Token: token, UserID: 1}},
			)
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			calls := 0

			// When
			middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(response, request)

			// Then
			if response.Code != test.wantStatus || calls != test.wantCalls {
				t.Fatalf("status=%d calls=%d, want status=%d calls=%d", response.Code, calls, test.wantStatus, test.wantCalls)
			}
		})
	}
}

type middlewareTestUserStore struct {
	user *User
}

func (*middlewareTestUserStore) CreateUser(context.Context, *User) error { return nil }

func (*middlewareTestUserStore) GetUserByUsername(context.Context, string) (*User, error) {
	return nil, ErrUserNotFound
}

func (store *middlewareTestUserStore) GetUserByID(context.Context, int64) (*User, error) {
	return store.user, nil
}

func (*middlewareTestUserStore) UpdateLastLogin(context.Context, int64) error { return nil }

type middlewareTestSessionReader struct {
	session *Session
}

func (reader middlewareTestSessionReader) GetSessionByToken(context.Context, string) (*Session, error) {
	return reader.session, nil
}
