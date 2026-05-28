package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicGlobalSituationReturnsSanitizedEmptyStateWithoutAuth(t *testing.T) {
	h := NewHandler(nil, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/public/situation/global", nil)
	rr := httptest.NewRecorder()

	h.PublicGlobalSituation(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if strings.Contains(strings.ToLower(rr.Body.String()), "token") || strings.Contains(strings.ToLower(rr.Body.String()), "password") || strings.Contains(strings.ToLower(rr.Body.String()), "secret") {
		t.Fatalf("public response leaked sensitive field: %s", rr.Body.String())
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("expected success envelope code 0, got %d", resp.Code)
	}
}

func TestPublicGlobalSituationRejectsMutation(t *testing.T) {
	h := NewHandler(nil, nil, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/public/situation/global", nil)
	rr := httptest.NewRecorder()

	h.PublicGlobalSituation(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}
}
