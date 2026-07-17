package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	controlPrincipalHeader = "X-Lyflow-Control-Principal"
	controlRoleHeader      = "X-Lyflow-Control-Role"
)

type reloadControl struct {
	token     string
	auditPath string
	mu        sync.Mutex
}

type reloadAuditRecord struct {
	OccurredAt time.Time `json:"occurred_at"`
	Principal  string    `json:"principal"`
	Role       string    `json:"role"`
	Result     string    `json:"result"`
	Stage      string    `json:"stage"`
	Revision   string    `json:"revision,omitempty"`
	Digest     string    `json:"digest,omitempty"`
}

func newReloadControl(token, auditPath string) (*reloadControl, error) {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(auditPath) == "" {
		return nil, errors.New("security-engine: reload control authentication and audit are required")
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		return nil, fmt.Errorf("create reload audit directory: %w", err)
	}
	return &reloadControl{token: token, auditPath: auditPath}, nil
}

func (c *reloadControl) authorize(request *http.Request) (string, string, int) {
	principal := strings.TrimSpace(request.Header.Get(controlPrincipalHeader))
	role := strings.TrimSpace(request.Header.Get(controlRoleHeader))
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	provided := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	if !strings.HasPrefix(authorization, "Bearer ") || subtle.ConstantTimeCompare([]byte(provided), []byte(c.token)) != 1 || principal == "" {
		return "anonymous", "", http.StatusUnauthorized
	}
	if role != "admin" {
		return principal, role, http.StatusForbidden
	}
	return principal, role, http.StatusOK
}

func (c *reloadControl) record(principal, role, result, stage, revision, digest string) error {
	record := reloadAuditRecord{OccurredAt: time.Now().UTC(), Principal: principal, Role: role, Result: result, Stage: stage, Revision: revision, Digest: digest}
	c.mu.Lock()
	defer c.mu.Unlock()
	file, err := os.OpenFile(c.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open reload audit: %w", err)
	}
	if err := json.NewEncoder(file).Encode(record); err != nil {
		_ = file.Close()
		return fmt.Errorf("append reload audit: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync reload audit: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close reload audit: %w", err)
	}
	return nil
}

func recordReloadFailure(writer http.ResponseWriter, control *reloadControl, principal, role, stage, revision string) bool {
	if err := control.record(principal, role, "failed", stage, revision, ""); err != nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(writer).Encode(map[string]any{"error": "reload_audit_unavailable"})
		return false
	}
	return true
}
