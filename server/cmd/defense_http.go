package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

// defenseSessionsHandler serves /api/v1/defense/sessions:
//
//	GET  list sessions (status=live|all)
//	POST create a manual defense session
func defenseSessionsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		runtime, err := defenseRuntimeFor(cfg)
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		switch r.Method {
		case http.MethodGet:
			statuses := defenseSessionStatusFilter(r.URL.Query().Get("status"))
			sessions, err := runtime.ListSessions(r.Context(), statuses, parseQueryInt(r.URL.Query().Get("limit"), 50))
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusOK, map[string]interface{}{"items": sessions, "total": len(sessions)})
		case http.MethodPost:
			var payload struct {
				Scope           string `json:"scope"`
				ScopeValue      string `json:"scope_value"`
				Mode            string `json:"mode"`
				DurationSeconds int    `json:"duration_seconds"`
				DryRunSeconds   *int   `json:"dry_run_seconds"`
				Reason          string `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body")
				return
			}
			request := DefenseSessionRequest{
				Scope:      payload.Scope,
				ScopeValue: payload.ScopeValue,
				Mode:       payload.Mode,
				Reason:     payload.Reason,
				Actor:      defenseActor(r),
				Duration:   time.Duration(payload.DurationSeconds) * time.Second,
			}
			if payload.DryRunSeconds != nil {
				request.DryRun = time.Duration(*payload.DryRunSeconds) * time.Second
				request.DryRunSet = true
			}
			session, err := runtime.CreateSession(r.Context(), request)
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusCreated, session)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

// defenseSessionActionHandler serves /api/v1/defense/sessions/{id} and
// /api/v1/defense/sessions/{id}/stop.
func defenseSessionActionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		runtime, err := defenseRuntimeFor(cfg)
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		suffix := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/defense/sessions/"), "/")
		if suffix == "" {
			writeJSONError(w, http.StatusNotFound, "defense_session_not_found", "defense session not found")
			return
		}
		id := suffix
		action := ""
		if index := strings.LastIndex(suffix, "/"); index >= 0 {
			id = suffix[:index]
			action = suffix[index+1:]
		}
		if id == "" {
			writeJSONError(w, http.StatusNotFound, "defense_session_not_found", "defense session not found")
			return
		}
		switch {
		case action == "" && r.Method == http.MethodGet:
			session, err := runtime.Session(r.Context(), id)
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusOK, session)
		case action == "stop" && r.Method == http.MethodPost:
			var payload struct {
				Reason string `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body")
				return
			}
			session, err := runtime.StopSession(r.Context(), id, defenseActor(r), payload.Reason)
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusOK, session)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

// defenseSchedulesHandler serves /api/v1/defense/schedules:
//
//	GET  list automatic windows
//	POST create an automatic window
func defenseSchedulesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		runtime, err := defenseRuntimeFor(cfg)
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		switch r.Method {
		case http.MethodGet:
			schedules, err := runtime.ListSchedules(r.Context())
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusOK, map[string]interface{}{"items": schedules, "total": len(schedules)})
		case http.MethodPost:
			var request DefenseScheduleRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body")
				return
			}
			request.Actor = defenseActor(r)
			schedule, err := runtime.CreateSchedule(r.Context(), request)
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusCreated, schedule)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

// defenseScheduleActionHandler serves /api/v1/defense/schedules/{id}:
//
//	PUT    update fields (including enabled)
//	POST   toggle enabled
//	DELETE soft delete the rule
func defenseScheduleActionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		runtime, err := defenseRuntimeFor(cfg)
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/defense/schedules/"), "/")
		if id == "" || strings.Contains(id, "/") {
			writeJSONError(w, http.StatusNotFound, "defense_schedule_not_found", "defense schedule not found")
			return
		}
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			var request DefenseScheduleRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body")
				return
			}
			request.Actor = defenseActor(r)
			schedule, err := runtime.UpdateSchedule(r.Context(), id, request)
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusOK, schedule)
		case http.MethodDelete:
			var request struct {
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			schedule, err := runtime.DeleteSchedule(r.Context(), id, defenseActor(r), request.Reason)
			if err != nil {
				writeDefenseError(w, err)
				return
			}
			writeDefenseSuccess(w, http.StatusOK, schedule)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

// defenseStatusHandler serves /api/v1/defense/status: the current live session,
// remaining seconds, schedule windows and the tag list used by the console form.
func defenseStatusHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		runtime, err := defenseRuntimeFor(cfg)
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		status, err := runtime.Status(r.Context())
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		writeDefenseSuccess(w, http.StatusOK, status)
	}
}

// defenseAuditHandler serves /api/v1/defense/audit: who switched what, when,
// and whether it succeeded.
func defenseAuditHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		runtime, err := defenseRuntimeFor(cfg)
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		rows, err := runtime.Audit(r.Context(), parseQueryInt(r.URL.Query().Get("limit"), 100))
		if err != nil {
			writeDefenseError(w, err)
			return
		}
		writeDefenseSuccess(w, http.StatusOK, map[string]interface{}{"items": rows, "total": len(rows)})
	}
}

func defenseSessionStatusFilter(value string) []string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "live":
		return []string{DefenseStatusDryRun, DefenseStatusActive}
	case "", "all":
		return nil
	default:
		return []string{strings.ToLower(strings.TrimSpace(value))}
	}
}

func defenseActor(r *http.Request) string {
	if r == nil {
		return "api"
	}
	if id := auth.GetUserIDFromContext(r.Context()); id > 0 {
		return "user:" + strconv.FormatInt(id, 10)
	}
	return "api"
}

func writeDefenseSuccess(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": data})
}

func writeDefenseError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "defense_failed"
	switch {
	case errors.Is(err, errDefenseValidation):
		status, code = http.StatusBadRequest, "invalid_defense_request"
	case errors.Is(err, errDefenseConflict):
		status, code = http.StatusConflict, "defense_session_conflict"
	case errors.Is(err, errDefenseBlockDisabled):
		status, code = http.StatusConflict, "defense_block_disabled"
	case errors.Is(err, errDefenseMonitorBaseline):
		status, code = http.StatusConflict, "defense_monitor_baseline_required"
	case errors.Is(err, errDefenseNoAgents):
		status, code = http.StatusUnprocessableEntity, "defense_scope_empty"
	case errors.Is(err, errDefenseNotFound):
		status, code = http.StatusNotFound, "defense_not_found"
	case errors.Is(err, errDefenseUnavailable):
		status, code = http.StatusServiceUnavailable, "defense_unavailable"
	}
	writeJSONError(w, status, code, err.Error())
}
