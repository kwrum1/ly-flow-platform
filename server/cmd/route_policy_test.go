package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func TestRouteRegistryEnforcesRoutePolicyForProtectedRoutes(t *testing.T) {
	t.Run("unknown route rejects before handler", func(t *testing.T) {
		// Given
		request := httptest.NewRequest(http.MethodGet, "/api/v1/not-registered", nil)
		response := httptest.NewRecorder()
		called := 0

		// When
		EnforceRoutePolicy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called++
		}), nil).ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", response.Code)
		}
		if called != 0 {
			t.Fatalf("handler calls=%d, want 0", called)
		}
	})

	t.Run("protected routes enforce authz through policy layer", func(t *testing.T) {
		for _, route := range ArchitectureRouteSnapshot {
			route := route
			if route.Public {
				continue
			}
			if route.LoopbackOnly {
				t.Run(route.Path, func(t *testing.T) {
					testLoopbackPolicy(t, route)
				})
				continue
			}
			if route.AgentCredential {
				t.Run(route.Path, func(t *testing.T) {
					request := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(`{}`))
					response := httptest.NewRecorder()
					EnforceRoutePolicy(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						writeJSONError(w, http.StatusUnauthorized, "agent_auth_required", "valid Agent credential required")
					}), nil).ServeHTTP(response, request)
					if response.Code != http.StatusUnauthorized {
						t.Fatalf("status=%d, want internal Agent auth response", response.Code)
					}
				})
				continue
			}
			if !rolesEqual(route.ReadRoles, allRoles) && !rolesEqual(route.ReadRoles, adminRoles) {
				t.Fatalf("unexpected read roles for %s: %#v", route.Path, route.ReadRoles)
			}
			if !rolesEqual(route.WriteRoles, operatorRoles) && !rolesEqual(route.WriteRoles, adminRoles) {
				t.Fatalf("unexpected write roles for %s: %#v", route.Path, route.WriteRoles)
			}

			t.Run(route.Path, func(t *testing.T) {
				testProtectedRoutePolicy(t, route)
			})
		}
	})
}

func testProtectedRoutePolicy(t *testing.T, route RouteSpec) {
	t.Helper()
	requestPath := routeRequestPath(route.Path)

	t.Run("unauthenticated rejects", func(t *testing.T) {
		// Given
		request := httptest.NewRequest(http.MethodGet, requestPath, nil)
		response := httptest.NewRecorder()
		called := 0

		// When
		EnforceRoutePolicy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called++
		}), newTestRouteAuthMiddleware(auth.RoleViewer)).ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want 401", response.Code)
		}
		if called != 0 {
			t.Fatalf("handler calls=%d, want 0", called)
		}
	})

	if rolesEqual(route.ReadRoles, allRoles) && rolesEqual(route.WriteRoles, operatorRoles) {
		t.Run("viewer reads succeed", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodGet, auth.RoleViewer, http.StatusOK, 1)
		})
		t.Run("viewer writes reject", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodPost, auth.RoleViewer, http.StatusForbidden, 0)
		})
		t.Run("analyst writes succeed", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodPost, auth.RoleAnalyst, http.StatusOK, 1)
		})
		return
	}

	if rolesEqual(route.ReadRoles, adminRoles) && rolesEqual(route.WriteRoles, adminRoles) {
		t.Run("analyst reads reject", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodGet, auth.RoleAnalyst, http.StatusForbidden, 0)
		})
		t.Run("admin reads succeed", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodGet, auth.RoleAdmin, http.StatusOK, 1)
		})
		t.Run("analyst writes reject", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodPost, auth.RoleAnalyst, http.StatusForbidden, 0)
		})
		t.Run("admin writes succeed", func(t *testing.T) {
			expectPolicyOutcome(t, route, http.MethodPost, auth.RoleAdmin, http.StatusOK, 1)
		})
		return
	}

	t.Fatalf("unexpected route policy for %s: read=%#v write=%#v", route.Path, route.ReadRoles, route.WriteRoles)
}

func testLoopbackPolicy(t *testing.T, route RouteSpec) {
	t.Helper()
	requestPath := routeRequestPath(route.Path)

	t.Run("remote reject", func(t *testing.T) {
		// Given
		request := httptest.NewRequest(http.MethodPost, requestPath, nil)
		request.RemoteAddr = "192.0.2.10:1234"
		response := httptest.NewRecorder()
		called := 0

		// When
		EnforceRoutePolicy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called++
		}), nil).ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", response.Code)
		}
		if called != 0 {
			t.Fatalf("handler calls=%d, want 0", called)
		}
	})

	t.Run("loopback succeeds", func(t *testing.T) {
		// Given
		request := httptest.NewRequest(http.MethodPost, requestPath, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		called := 0

		// When
		EnforceRoutePolicy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called++
			response.WriteHeader(http.StatusNoContent)
		}), nil).ServeHTTP(response, request)

		// Then
		if response.Code != http.StatusNoContent {
			t.Fatalf("status=%d, want 204", response.Code)
		}
		if called != 1 {
			t.Fatalf("handler calls=%d, want 1", called)
		}
	})
}

func expectPolicyOutcome(t *testing.T, route RouteSpec, method string, role auth.UserRole, wantStatus int, wantCalls int) {
	t.Helper()
	request := httptest.NewRequest(method, routeRequestPath(route.Path), nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	response := httptest.NewRecorder()
	calls := 0

	EnforceRoutePolicy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
		response.WriteHeader(http.StatusOK)
	}), newTestRouteAuthMiddleware(role)).ServeHTTP(response, request)

	if response.Code != wantStatus {
		t.Fatalf("status=%d, want %d", response.Code, wantStatus)
	}
	if calls != wantCalls {
		t.Fatalf("handler calls=%d, want %d", calls, wantCalls)
	}
}

func routeRequestPath(path string) string {
	if strings.Contains(path, "{id}") {
		return strings.ReplaceAll(path, "{id}", "123")
	}
	return path
}

const testToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newTestRouteAuthMiddleware(role auth.UserRole) *auth.Middleware {
	return auth.NewMiddleware(
		auth.NewService("test-secret", time.Hour),
		&testRouteUserStore{role: role},
		&testRouteSessionStore{token: testToken},
	)
}

type testRouteUserStore struct {
	role auth.UserRole
}

func (s *testRouteUserStore) CreateUser(context.Context, *auth.User) error { return nil }

func (s *testRouteUserStore) GetUserByUsername(context.Context, string) (*auth.User, error) {
	return &auth.User{ID: 1, Role: s.role, IsActive: true}, nil
}

func (s *testRouteUserStore) GetUserByID(_ context.Context, id int64) (*auth.User, error) {
	return &auth.User{ID: id, Role: s.role, IsActive: true}, nil
}

func (s *testRouteUserStore) UpdateLastLogin(context.Context, int64) error { return nil }

type testRouteSessionStore struct {
	token string
}

func (s *testRouteSessionStore) GetSessionByToken(_ context.Context, token string) (*auth.Session, error) {
	if token != s.token {
		return nil, auth.ErrTokenInvalid
	}
	return &auth.Session{Token: token, UserID: 1}, nil
}
