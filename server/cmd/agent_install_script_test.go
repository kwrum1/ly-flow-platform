package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentInstallScriptCarriesOneTimeEnrollmentToken(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://agent.example/api/v1/agent/install.sh?enrollment_token=abc123", nil)
	response := httptest.NewRecorder()
	agentInstallScriptHandler(&Config{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `ENROLL_TOKEN="abc123"`) {
		t.Fatalf("install script does not carry token: %s", body[:300])
	}
	if !strings.Contains(body, "EnvironmentFile=-/opt/ly-agent/etc/agent.env") {
		t.Fatal("install script does not load enrollment environment")
	}
	if !strings.Contains(body, "AGENT_REQUIRE_BINARY_INTEGRITY=$AGENT_INTEGRITY_FLAG") {
		t.Fatal("install script does not persist signed binary integrity setting")
	}
	if strings.Contains(body, "Environment=AGENT_REQUIRE_BINARY_INTEGRITY=false") {
		t.Fatal("install script hard-disables signed binary integrity")
	}
	enrollIndex := strings.Index(body, "AGENT_ENROLL_TOKEN=$ENROLL_TOKEN")
	integrityIndex := strings.Index(body, "AGENT_REQUIRE_BINARY_INTEGRITY=$AGENT_INTEGRITY_FLAG")
	if enrollIndex < 0 || integrityIndex < 0 || enrollIndex > integrityIndex {
		t.Fatalf("install environment order is unsafe: enroll=%d integrity=%d", enrollIndex, integrityIndex)
	}
}

func TestAgentInstallScriptRejectsUnsafeEnrollmentToken(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://agent.example/api/v1/agent/install.sh?enrollment_token=abc%22%3Brm", nil)
	response := httptest.NewRecorder()
	agentInstallScriptHandler(&Config{}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", response.Code)
	}
}
