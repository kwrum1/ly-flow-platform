package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentidentity"
)

type agentIdentityControlRequest struct {
	Action       string `json:"action"`
	AgentID      string `json:"agent_id"`
	State        string `json:"state"`
	Token        string `json:"token"`
	Version      uint64 `json:"version"`
	TTLMinutes   int    `json:"ttl_minutes"`
	OverlapHours int    `json:"overlap_hours"`
}

func agentIdentityControlHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if cfg == nil || cfg.AgentIdentity == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "agent_identity_unavailable", "Agent identity service unavailable")
			return
		}
		var request agentIdentityControlRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_agent_identity_request", "invalid Agent identity request")
			return
		}
		id, err := agentidentity.NewAgentID(strings.TrimSpace(request.AgentID))
		if err != nil {
			writeAgentIdentityError(w, err)
			return
		}
		data, err := executeAgentIdentityControl(cfg.AgentIdentity, id, request)
		if err != nil {
			writeAgentIdentityError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": data})
	}
}

func executeAgentIdentityControl(manager *agentidentity.Manager, id agentidentity.AgentID, request agentIdentityControlRequest) (map[string]interface{}, error) {
	switch strings.TrimSpace(request.Action) {
	case "issue_enrollment":
		token, err := manager.IssueEnrollmentToken(id.String(), boundedTokenTTL(request.TTLMinutes))
		return map[string]interface{}{"agent_id": id.String(), "enrollment_token": token}, err
	case "transition":
		state, err := agentidentity.ParseState(request.State)
		if err != nil {
			return nil, err
		}
		return identityStatus(manager, id, manager.Transition(id, state, request.Version))
	case "rotate":
		credential, err := generateAgentCredential()
		if err != nil {
			return nil, err
		}
		overlap := time.Duration(request.OverlapHours) * time.Hour
		if err := manager.BeginRotation(id, credential, overlap, request.Version); err != nil {
			return nil, err
		}
		data, err := identityStatus(manager, id, nil)
		data["agent_credential"] = credential
		return data, err
	case "retire_legacy":
		return identityStatus(manager, id, manager.RetireLegacy(id, request.Version))
	case "rollback":
		return identityStatus(manager, id, manager.Rollback(id, request.Version))
	case "revoke":
		return identityStatus(manager, id, manager.Revoke(id, request.Version))
	case "issue_recovery":
		token, err := manager.IssueRecoveryToken(id, boundedTokenTTL(request.TTLMinutes))
		return map[string]interface{}{"agent_id": id.String(), "recovery_token": token}, err
	case "recover":
		credential, err := generateAgentCredential()
		if err != nil {
			return nil, err
		}
		record, err := manager.Recover(strings.TrimSpace(request.Token), credential)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"agent_id": record.ID().String(), "state": record.State(), "version": record.Version(), "agent_credential": credential}, nil
	default:
		return nil, agentidentity.ErrInvalidTransition
	}
}

func identityStatus(manager *agentidentity.Manager, id agentidentity.AgentID, operationErr error) (map[string]interface{}, error) {
	if operationErr != nil {
		return nil, operationErr
	}
	state, version, err := manager.Status(id)
	return map[string]interface{}{"agent_id": id.String(), "state": state, "version": version}, err
}

func boundedTokenTTL(minutes int) time.Duration {
	if minutes <= 0 || minutes > 15 {
		return 15 * time.Minute
	}
	return time.Duration(minutes) * time.Minute
}

func writeAgentIdentityError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	code := "agent_identity_conflict"
	if errors.Is(err, agentidentity.ErrInvalidAgentID) || errors.Is(err, agentidentity.ErrInvalidCredential) || errors.Is(err, agentidentity.ErrOverlapTooLong) {
		status, code = http.StatusBadRequest, "invalid_agent_identity_request"
	}
	if errors.Is(err, agentidentity.ErrTokenUnknown) || errors.Is(err, agentidentity.ErrTokenExpired) || errors.Is(err, agentidentity.ErrTokenUsed) || errors.Is(err, agentidentity.ErrCredentialRejected) {
		status, code = http.StatusUnauthorized, "agent_identity_unauthorized"
	}
	writeJSONError(w, status, code, "Agent identity operation rejected")
}
