package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func securityEventsHandler(runtime *StorageEventRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if runtime == nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "migration_unavailable", "event migration unavailable")
			return
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/security-events":
			var event contracts.CanonicalSecurityEvent
			decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 2<<20))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&event); err != nil {
				writeJSONError(writer, http.StatusBadRequest, "invalid_security_event", "invalid security event")
				return
			}
			if err := runtime.WriteCanonical(request.Context(), event); err != nil {
				writeJSONError(writer, http.StatusServiceUnavailable, "security_event_store_failed", err.Error())
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(struct {
				EventUID string `json:"event_uid"`
			}{EventUID: event.EventUID})
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/security-events":
			readStoredEvents(writer, request, runtime, contracts.GovernanceRead)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/security-events/export":
			readStoredEvents(writer, request, runtime, contracts.GovernanceExport)
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/security-events/"):
			deleteStoredEvent(writer, request, runtime)
		default:
			writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	})
}

func readStoredEvents(writer http.ResponseWriter, request *http.Request, runtime *StorageEventRuntime, action contracts.GovernanceAction) {
	limit, err := strconv.ParseInt(request.URL.Query().Get("limit"), 10, 64)
	if err != nil || limit <= 0 {
		limit = 100
	}
	events, source, err := runtime.Read(request.Context(), limit)
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "security_event_read_failed", err.Error())
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
		ReadSource string                             `json:"read_source"`
		Events     []contracts.CanonicalSecurityEvent `json:"events"`
	}{ReadSource: string(source), Events: events})
}

func deleteStoredEvent(writer http.ResponseWriter, request *http.Request, runtime *StorageEventRuntime) {
	eventUID := strings.TrimPrefix(request.URL.Path, "/api/v1/security-events/")
	if eventUID == "" || eventUID == "export" {
		writeJSONError(writer, http.StatusBadRequest, "event_uid_required", "event UID required")
		return
	}
	events, _, err := runtime.Read(request.Context(), 1000)
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "security_event_read_failed", err.Error())
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
			writeJSONError(writer, http.StatusServiceUnavailable, "event_delete_failed", err.Error())
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSONError(writer, http.StatusNotFound, "event_not_found", "event not found")
}
