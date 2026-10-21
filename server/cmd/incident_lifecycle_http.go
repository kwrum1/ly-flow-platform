package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

func incidentsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		if limit <= 0 {
			limit = 50
		}
		if offset < 0 {
			offset = 0
		}
		if cfg == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", "persistent incident lifecycle unavailable")
			return
		}
		var activeResult xdrActiveRouteResult
		// Incident list reads are latency-sensitive and are often used for the
		// first dashboard paint. `live=0` serves durable state without running
		// the expensive active-graph sync; the refresh action explicitly asks
		// for live synchronization.
		liveSync := r.URL.Query().Get("live") != "0"
		if liveSync && cfg.XDRGraph != nil && cfg.XDRInput != nil {
			var err error
			activeResult, err = xdrActiveChainsResponse(r.Context(), cfg, offset+limit+50)
			if err != nil {
				if cfg.Incidents == nil {
					writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", err.Error())
					return
				}
				log.Printf("incident live sync unavailable; serving durable state: %v", err)
				activeResult = nil
			}
		}
		if cfg.Incidents == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", "persistent incident lifecycle unavailable")
			return
		}
		if activeResult != nil {
			if err := syncActiveIncidentLifecycle(r.Context(), cfg, activeResult); err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "incident_sync_failed", err.Error())
				return
			}
		}
		persisted, total, err := cfg.Incidents.ListFiltered(r.Context(), limit, offset,
			r.URL.Query().Get("status"), r.URL.Query().Get("severity"))
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", err.Error())
			return
		}
		items := make([]map[string]interface{}, 0, len(persisted))
		for _, incident := range persisted {
			items = append(items, incidentJSONRow(incident))
		}
		data := map[string]interface{}{"items": items, "total": total, "limit": limit, "offset": offset}
		if cfg.IncidentSnapshot != nil {
			data["legacy_snapshot"] = cfg.IncidentSnapshot.report
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": data})
	}
}

func incidentDetailHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", "persistent incident lifecycle unavailable")
			return
		}
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/"), "/")
		parts := strings.Split(path, "/")
		id := parts[0]
		if id == "" {
			writeJSONError(w, http.StatusNotFound, "incident_not_found", "incident not found")
			return
		}
		if cfg.Incidents == nil {
			if r.Method == http.MethodPut && len(parts) == 2 && parts[1] == "status" {
				legacyIncidentStatusHandler(cfg, id).ServeHTTP(w, r)
				return
			}
			writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", "persistent incident lifecycle unavailable")
			return
		}
		if r.Method == http.MethodPut && len(parts) == 2 {
			incidentMutationHandler(cfg, id, parts[1]).ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet || len(parts) != 1 {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if r.URL.Query().Get("live") == "1" && cfg.XDRGraph != nil && cfg.XDRInput != nil {
			activeResult, err := xdrActiveChainsResponse(r.Context(), cfg, 100)
			if err == nil {
				if err := syncActiveIncidentLifecycle(r.Context(), cfg, activeResult); err != nil {
					writeJSONError(w, http.StatusServiceUnavailable, "incident_sync_failed", err.Error())
					return
				}
			}
		}
		incident, err := cfg.Incidents.Get(r.Context(), id)
		if errors.Is(err, incidentlifecycle.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "incident_not_found", "incident not found")
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "incident_load_failed", err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": incidentJSONRow(incident)})
	}
}

func incidentMutationHandler(cfg *Config, id, actionName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Status          string `json:"status"`
			Assignee        string `json:"assignee"`
			Reason          string `json:"reason"`
			SuppressedUntil string `json:"suppressed_until"`
			IdempotencyKey  string `json:"idempotency_key"`
			ExpectedVersion int64  `json:"expected_version"`
			Disposition     string `json:"disposition"`
			SuppressScope   string `json:"suppress_scope"`
			SuppressValue   string `json:"suppress_value"`
			SuppressDays    int    `json:"suppress_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
			return
		}
		current, err := cfg.Incidents.Get(r.Context(), id)
		if err != nil {
			writeIncidentLifecycleError(w, err)
			return
		}
		if request.ExpectedVersion == 0 {
			request.ExpectedVersion = current.Version
		}
		actor := incidentActor(r.Context())
		if actionName == "status" && strings.EqualFold(strings.TrimSpace(request.Status), string(incidentlifecycle.StatusClosed)) {
			disposition := strings.ToLower(strings.TrimSpace(request.Disposition))
			if disposition == "" {
				disposition = "resolved"
			}
			reason := strings.TrimSpace(request.Reason)
			if reason == "" {
				writeJSONError(w, http.StatusBadRequest, "closure_reason_required", "closure reason is required")
				return
			}
			updated, err := closeIncidentWithDisposition(r.Context(), cfg, current, actor, disposition, reason)
			if err != nil {
				writeIncidentLifecycleError(w, err)
				return
			}
			if refreshed, getErr := cfg.Incidents.Get(r.Context(), id); getErr == nil {
				updated = refreshed
			}
			response := incidentJSONRow(updated)
			if scope := strings.ToLower(strings.TrimSpace(request.SuppressScope)); scope != "" && scope != "none" {
				days := request.SuppressDays
				if days <= 0 {
					days = 30
				}
				if days > 365 {
					days = 365
				}
				entry := xdrSuppressionEntry{
					Scope: scope, Value: strings.TrimSpace(request.SuppressValue),
					Reason: reason, IncidentID: id, CreatedBy: actor.ID,
					CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour),
				}
				if entry.Value == "" {
					writeJSONError(w, http.StatusBadRequest, "suppression_value_required", "suppression value is required")
					return
				}
				if err := addXDRSuppression(cfg, entry); err != nil {
					writeJSONError(w, http.StatusInternalServerError, "suppression_save_failed", err.Error())
					return
				}
				response["suppression"] = entry
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": response})
			return
		}
		command := incidentlifecycle.Command{IncidentID: id, IdempotencyKey: strings.TrimSpace(request.IdempotencyKey), Actor: actor, ExpectedVersion: request.ExpectedVersion, Reason: strings.TrimSpace(request.Reason)}
		switch actionName {
		case "status":
			command.Action = incidentlifecycle.ActionTransition
			command.To = incidentlifecycle.Status(strings.ToLower(strings.TrimSpace(request.Status)))
		case "assign":
			command.Action = incidentlifecycle.ActionAssign
			command.Assignee = strings.TrimSpace(request.Assignee)
		case "suppress":
			command.Action = incidentlifecycle.ActionSuppress
			command.SuppressUntil, err = time.Parse(time.RFC3339, strings.TrimSpace(request.SuppressedUntil))
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_suppression_expiry", "suppressed_until must be RFC3339")
				return
			}
		default:
			writeJSONError(w, http.StatusNotFound, "incident_action_not_found", "incident action not found")
			return
		}
		if command.IdempotencyKey == "" {
			command.IdempotencyKey = incidentCommandIdempotencyKey(command)
		}
		updated, err := cfg.Incidents.Apply(r.Context(), command)
		if err != nil {
			writeIncidentLifecycleError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": incidentJSONRow(updated)})
	}
}

func closeIncidentWithDisposition(ctx context.Context, cfg *Config, current incidentlifecycle.Incident, actor incidentlifecycle.Actor, disposition, reason string) (incidentlifecycle.Incident, error) {
	if cfg == nil || cfg.Incidents == nil {
		return incidentlifecycle.Incident{}, incidentlifecycle.ErrNotFound
	}
	path := make([]incidentlifecycle.Status, 0, 4)
	switch current.Status {
	case incidentlifecycle.StatusOpen:
		path = append(path, incidentlifecycle.StatusTriaged, incidentlifecycle.StatusProcessing, incidentlifecycle.StatusResolved, incidentlifecycle.StatusClosed)
	case incidentlifecycle.StatusTriaged:
		path = append(path, incidentlifecycle.StatusProcessing, incidentlifecycle.StatusResolved, incidentlifecycle.StatusClosed)
	case incidentlifecycle.StatusProcessing:
		path = append(path, incidentlifecycle.StatusResolved, incidentlifecycle.StatusClosed)
	case incidentlifecycle.StatusResolved:
		path = append(path, incidentlifecycle.StatusClosed)
	case incidentlifecycle.StatusClosed:
		return current, nil
	default:
		return incidentlifecycle.Incident{}, incidentlifecycle.ErrIllegalTransition
	}
	auditReason := "[" + disposition + "] " + reason
	updated := current
	for _, next := range path {
		command := incidentlifecycle.Command{
			IncidentID:     current.ID,
			IdempotencyKey: "disposition:" + current.ID + ":" + disposition + ":" + strconv.FormatInt(current.Version, 10) + ":" + string(next),
			Actor:          actor,
			Action:         incidentlifecycle.ActionTransition,
			To:             next,
			Reason:         auditReason,
		}
		var err error
		updated, err = cfg.Incidents.Apply(ctx, command)
		if err != nil {
			return incidentlifecycle.Incident{}, err
		}
	}
	return updated, nil
}

func incidentCommandIdempotencyKey(command incidentlifecycle.Command) string {
	return "incident:" + incidentlifecycle.CommandPayloadHash(command)
}

func writeIncidentLifecycleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, incidentlifecycle.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "incident_not_found", "incident not found")
	case errors.Is(err, incidentlifecycle.ErrForbidden):
		writeJSONError(w, http.StatusForbidden, "incident_action_forbidden", "incident action forbidden")
	case errors.Is(err, incidentlifecycle.ErrConflict):
		writeJSONError(w, http.StatusConflict, "incident_version_conflict", "incident version conflict")
	case errors.Is(err, incidentlifecycle.ErrIllegalTransition):
		writeJSONError(w, http.StatusConflict, "illegal_incident_transition", "illegal incident transition")
	case errors.Is(err, incidentlifecycle.ErrInvalidCommand):
		writeJSONError(w, http.StatusBadRequest, "invalid_incident_action", "invalid incident action")
	default:
		writeJSONError(w, http.StatusServiceUnavailable, "incident_persistence_failed", err.Error())
	}
}
