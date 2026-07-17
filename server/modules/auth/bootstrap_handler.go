package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type BootstrapHandler struct {
	manager *BootstrapTokenManager
}

func NewBootstrapHandler(manager *BootstrapTokenManager) *BootstrapHandler {
	return &BootstrapHandler{manager: manager}
}

func (h *BootstrapHandler) Consume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeAuthError(w, http.StatusForbidden, "loopback_required", "loopback required")
		return
	}
	active, err := h.manager.Active(r.Context())
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "bootstrap_failed", "bootstrap failed")
		return
	}
	if !active {
		writeAuthError(w, http.StatusNotFound, "bootstrap_closed", "bootstrap closed")
		return
	}
	var req BootstrapConsumeRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	trailing, err := io.ReadAll(io.MultiReader(decoder.Buffered(), r.Body))
	if err != nil || len(bytes.TrimSpace(trailing)) != 0 {
		writeAuthError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if err := h.manager.Consume(r.Context(), req); err != nil {
		switch {
		case errors.Is(err, ErrBootstrapTokenInvalid):
			writeAuthError(w, http.StatusNotFound, "bootstrap_closed", "bootstrap closed")
		case errors.Is(err, ErrBootstrapTokenExpired), errors.Is(err, ErrBootstrapTokenUsed), errors.Is(err, ErrBootstrapRecoveryState):
			writeAuthError(w, http.StatusNotFound, "bootstrap_closed", "bootstrap closed")
		default:
			writeAuthError(w, http.StatusInternalServerError, "bootstrap_failed", "bootstrap failed")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(Response{Code: 0, Message: "bootstrap complete"})
}
