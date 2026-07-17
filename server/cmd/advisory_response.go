package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/advisoryresponse"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

type advisorySubmitRequest struct {
	CandidateID    string                  `json:"candidate_id"`
	IncidentID     string                  `json:"incident_id"`
	AgentID        string                  `json:"agent_id"`
	Algorithm      string                  `json:"algorithm"`
	Action         advisoryresponse.Action `json:"action"`
	Target         string                  `json:"target"`
	Reason         string                  `json:"reason"`
	IdempotencyKey string                  `json:"idempotency_key"`
}

type advisoryApproveRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
}

func initializeAdvisoryResponseRuntime(cfg *Config) error {
	if cfg == nil || cfg.DBPool == nil {
		return fmt.Errorf("advisory response database unavailable")
	}
	store := advisoryresponse.NewPostgresStore(cfg.DBPool, nil, advisoryresponse.DefaultLimits())
	if err := store.EnsureSchema(context.Background()); err != nil {
		return err
	}
	cfg.AdvisoryResponses = store
	return nil
}

func advisoryResponseHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.AdvisoryResponses == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "advisory_response_unavailable", "advisory response unavailable")
			return
		}
		path := strings.TrimPrefix(request.URL.Path, "/api/v1/response/advisories")
		switch {
		case path == "" && request.Method == http.MethodGet:
			advisories, err := cfg.AdvisoryResponses.List(request.Context(), 100)
			if err != nil {
				writeAdvisoryError(w, err)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": advisories, "total": len(advisories), "execution": "disabled"}}); err != nil {
				return
			}
		case path == "" && request.Method == http.MethodPost:
			handleAdvisorySubmit(w, request, cfg)
		case strings.HasSuffix(path, "/approve") && request.Method == http.MethodPost:
			handleAdvisoryApprove(w, request, cfg)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "production response execution is disabled")
		}
	}
}

func handleAdvisorySubmit(w http.ResponseWriter, request *http.Request, cfg *Config) {
	var input advisorySubmitRequest
	if err := decodeAdvisoryJSON(w, request, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_advisory", err.Error())
		return
	}
	candidate, err := advisoryresponse.NewCandidate(advisoryresponse.CandidateInput{
		ID: input.CandidateID, IncidentID: input.IncidentID, AgentID: input.AgentID,
		Algorithm: input.Algorithm, Action: input.Action, Target: input.Target, Reason: input.Reason,
	})
	if err != nil {
		writeAdvisoryError(w, err)
		return
	}
	advisory, err := cfg.AdvisoryResponses.Submit(request.Context(), advisoryresponse.SubmitCommand{Candidate: candidate, Actor: advisoryActor(request), IdempotencyKey: input.IdempotencyKey})
	if err != nil {
		writeAdvisoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": advisory}); err != nil {
		return
	}
}

func handleAdvisoryApprove(w http.ResponseWriter, request *http.Request, cfg *Config) {
	var input advisoryApproveRequest
	if err := decodeAdvisoryJSON(w, request, &input); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_advisory_approval", err.Error())
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/api/v1/response/advisories/")
	id := strings.TrimSuffix(path, "/approve")
	advisory, err := cfg.AdvisoryResponses.Approve(request.Context(), advisoryresponse.ApprovalCommand{AdvisoryID: id, Actor: advisoryActor(request), IdempotencyKey: input.IdempotencyKey})
	if err != nil {
		writeAdvisoryError(w, err)
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": advisory}); err != nil {
		return
	}
}

func decodeAdvisoryJSON[T any](w http.ResponseWriter, request *http.Request, target *T) error {
	request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode advisory request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode advisory request: trailing data")
	}
	return nil
}

func advisoryActor(request *http.Request) advisoryresponse.Actor {
	return advisoryresponse.Actor{
		ID:   fmt.Sprintf("user:%d", auth.GetUserIDFromContext(request.Context())),
		Role: advisoryresponse.Role(auth.GetRoleFromContext(request.Context())),
	}
}

func writeAdvisoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, advisoryresponse.ErrActiveInputRequired):
		writeJSONError(w, http.StatusBadRequest, "active_input_required", err.Error())
	case errors.Is(err, advisoryresponse.ErrUnsupportedAction):
		writeJSONError(w, http.StatusBadRequest, "unsupported_action", err.Error())
	case errors.Is(err, advisoryresponse.ErrInvalidCandidate):
		writeJSONError(w, http.StatusBadRequest, "invalid_candidate", err.Error())
	case errors.Is(err, advisoryresponse.ErrVerificationRequired):
		writeJSONError(w, http.StatusConflict, "verification_required", err.Error())
	case errors.Is(err, advisoryresponse.ErrTwoPersonRequired):
		writeJSONError(w, http.StatusConflict, "two_person_required", err.Error())
	case errors.Is(err, advisoryresponse.ErrStaleIncident):
		writeJSONError(w, http.StatusConflict, "stale_incident", err.Error())
	case errors.Is(err, advisoryresponse.ErrAgentUnhealthy):
		writeJSONError(w, http.StatusConflict, "agent_unhealthy", err.Error())
	case errors.Is(err, advisoryresponse.ErrConflict):
		writeJSONError(w, http.StatusConflict, "advisory_conflict", err.Error())
	case errors.Is(err, advisoryresponse.ErrForbidden):
		writeJSONError(w, http.StatusForbidden, "advisory_forbidden", err.Error())
	case errors.Is(err, advisoryresponse.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "advisory_not_found", err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "advisory_response_failed", err.Error())
	}
}
