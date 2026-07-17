package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func redisSecurityEventsHandler(runtime *EventMigrationRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if runtime == nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "migration_unavailable", "event migration unavailable")
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/security-events":
			readGovernedEvents(writer, request, runtime, contracts.GovernanceRead)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/security-events/export":
			readGovernedEvents(writer, request, runtime, contracts.GovernanceExport)
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/security-events/"):
			deleteGovernedEvent(writer, request, runtime)
		default:
			writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	})
}

func readGovernedEvents(writer http.ResponseWriter, request *http.Request, runtime *EventMigrationRuntime, action contracts.GovernanceAction) {
	limit, err := strconv.ParseInt(request.URL.Query().Get("limit"), 10, 64)
	if err != nil || limit <= 0 {
		limit = 100
	}
	events, source, err := runtime.Read(request.Context(), limit)
	if err != nil {
		writeJSONError(writer, http.StatusUnprocessableEntity, "canonical_event_rejected", err.Error())
		return
	}
	role := governanceRole(auth.GetRoleFromContext(request.Context()), action)
	for _, event := range events {
		if err := contracts.AuthorizeGovernance(event, role, action); err != nil {
			writeGovernanceError(writer, err)
			return
		}
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		ReadSource contracts.ReadSource               `json:"read_source"`
		Events     []contracts.CanonicalSecurityEvent `json:"events"`
	}{ReadSource: source, Events: events})
}

func deleteGovernedEvent(writer http.ResponseWriter, request *http.Request, runtime *EventMigrationRuntime) {
	eventUID := strings.TrimPrefix(request.URL.Path, "/api/v1/security-events/")
	if eventUID == "" || eventUID == "export" {
		writeJSONError(writer, http.StatusBadRequest, "event_uid_required", "event UID required")
		return
	}
	events, _, err := runtime.Read(request.Context(), 1000)
	if err != nil {
		writeJSONError(writer, http.StatusUnprocessableEntity, "canonical_event_rejected", err.Error())
		return
	}
	for _, event := range events {
		if event.EventUID != eventUID {
			continue
		}
		role := governanceRole(auth.GetRoleFromContext(request.Context()), contracts.GovernanceDelete)
		if err := contracts.AuthorizeGovernance(event, role, contracts.GovernanceDelete); err != nil {
			writeGovernanceError(writer, err)
			return
		}
		if err := runtime.Delete(request.Context(), eventUID); err != nil {
			writeJSONError(writer, http.StatusInternalServerError, "event_delete_failed", err.Error())
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSONError(writer, http.StatusNotFound, "event_not_found", "event not found")
}

func governanceRole(role auth.UserRole, action contracts.GovernanceAction) contracts.GovernanceRole {
	switch role {
	case auth.RoleAdmin:
		if action == contracts.GovernanceDelete {
			return contracts.RolePrivacyAdmin
		}
		return contracts.RoleSecurityAdmin
	case auth.RoleAnalyst:
		return contracts.RoleAnalyst
	case auth.RoleViewer:
		return contracts.RoleViewer
	default:
		return contracts.RoleViewer
	}
}

func writeGovernanceError(writer http.ResponseWriter, err error) {
	status := http.StatusUnprocessableEntity
	code := "canonical_event_invalid"
	if errors.Is(err, contracts.ErrGovernanceDenied) {
		status = http.StatusForbidden
		code = "governance_denied"
	}
	writeJSONError(writer, status, code, err.Error())
}
