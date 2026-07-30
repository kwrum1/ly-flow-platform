package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func TestAuthLivePasswordChangeSessionAndProtectedConfigRoutes(t *testing.T) {
	// Given
	postgres := startIncidentLifecyclePostgres(t)
	t.Setenv("LYFLOW_TEST_POSTGRES_DSN", postgres.dsn)
	pool, ctx := xdrMigrationTestPool(t)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS auth_sessions, bootstrap_tokens, bootstrap_audit, users CASCADE`); err != nil {
		t.Fatalf("reset auth tables: %v", err)
	}
	userStore := auth.NewPostgresStore(pool)
	if err := userStore.InitSchema(ctx); err != nil {
		t.Fatalf("initialize auth schema: %v", err)
	}
	authService := auth.NewService("t06-live-secret", time.Hour)
	passwordHash, err := authService.HashPassword("Initial1!")
	if err != nil {
		t.Fatalf("hash initial password: %v", err)
	}
	user := &auth.User{
		Username: "t06-admin", PasswordHash: passwordHash, Role: auth.RoleAdmin,
		IsActive: true, MustChangePassword: true,
	}
	if err := userStore.CreateUser(ctx, user); err != nil {
		t.Fatalf("create live auth user: %v", err)
	}
	sessionStore := auth.NewSessionStore(pool)
	authHandler := auth.NewHandler(authService, userStore, sessionStore, pool)
	authMiddleware := auth.NewMiddleware(authService, userStore, sessionStore)
	t.Chdir(t.TempDir())
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("/api/v1/auth/logout", authHandler.Logout)
	mux.HandleFunc("/api/v1/auth/profile", authHandler.Profile)
	mux.HandleFunc("/api/v1/auth/change-password", authHandler.ChangePassword)
	mux.HandleFunc("/api/v1/system/time", systemTimeHandler())
	mux.HandleFunc("/api/v1/traffic/mirror-interface", mirrorCaptureConfigHandler(&Config{HostNetClassPath: t.TempDir()}))
	server := httptest.NewServer(EnforceRoutePolicy(mux, authMiddleware))
	t.Cleanup(server.Close)

	request := func(method, path, token, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("create %s request: %v", path, err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatalf("perform %s request: %v", path, err)
		}
		return response
	}
	login := func(password string) (int, string) {
		t.Helper()
		response := request(http.MethodPost, "/api/v1/auth/login", "", `{"username":"t06-admin","password":"`+password+`"}`)
		defer response.Body.Close()
		var envelope struct {
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		return response.StatusCode, envelope.Data.Token
	}
	expectStatus := func(response *http.Response, expected int) {
		t.Helper()
		defer response.Body.Close()
		if response.StatusCode != expected {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("status=%d body=%s, want %d", response.StatusCode, body, expected)
		}
	}

	// When
	loginStatus, firstToken := login("Initial1!")
	forcedResponse := request(http.MethodGet, "/api/v1/system/time", firstToken, "")
	changeResponse := request(http.MethodPost, "/api/v1/auth/change-password", firstToken, `{"old_password":"Initial1!","new_password":"Changed2!"}`)
	oldSessionResponse := request(http.MethodGet, "/api/v1/auth/profile", firstToken, "")
	oldPasswordStatus, _ := login("Initial1!")
	newLoginStatus, secondToken := login("Changed2!")
	systemTimeResponse := request(http.MethodGet, "/api/v1/system/time", secondToken, "")
	mirrorResponse := request(http.MethodGet, "/api/v1/traffic/mirror-interface", secondToken, "")
	logoutResponse := request(http.MethodPost, "/api/v1/auth/logout", secondToken, "")
	loggedOutResponse := request(http.MethodGet, "/api/v1/auth/profile", secondToken, "")

	// Then
	if loginStatus != http.StatusOK || firstToken == "" {
		t.Fatalf("initial login status=%d token_present=%v", loginStatus, firstToken != "")
	}
	expectStatus(forcedResponse, http.StatusPreconditionRequired)
	expectStatus(changeResponse, http.StatusOK)
	expectStatus(oldSessionResponse, http.StatusUnauthorized)
	if oldPasswordStatus != http.StatusUnauthorized || newLoginStatus != http.StatusOK || secondToken == "" {
		t.Fatalf("password lifecycle old=%d new=%d token_present=%v", oldPasswordStatus, newLoginStatus, secondToken != "")
	}
	expectStatus(systemTimeResponse, http.StatusOK)
	expectStatus(mirrorResponse, http.StatusOK)
	expectStatus(logoutResponse, http.StatusOK)
	expectStatus(loggedOutResponse, http.StatusUnauthorized)
}
