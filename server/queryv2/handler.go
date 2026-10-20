package queryv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/analytics"
)

type Store interface {
	QueryEventsV2(context.Context, analytics.EventV2Query) (analytics.EventV2Page, error)
	GetEventV2(context.Context, string) (analytics.EventV2View, error)
}

type Handler struct {
	Store Store
	Now   func() time.Time
}

func (handler Handler) List(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	query, err := parseQuery(request, handler.now())
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	page, err := handler.Store.QueryEventsV2(request.Context(), query)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "query_failed", "event query unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"code": 0, "message": "success", "data": page})
}

func (handler Handler) Get(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "GET required")
		return
	}
	uid := strings.TrimPrefix(request.URL.Path, "/api/v2/events/")
	uid = strings.TrimSpace(uid)
	if uid == "" || strings.Contains(uid, "/") {
		writeError(writer, http.StatusNotFound, "not_found", "event not found")
		return
	}
	event, err := handler.Store.GetEventV2(request.Context(), uid)
	if errors.Is(err, analytics.ErrEventV2NotFound) {
		writeError(writer, http.StatusNotFound, "not_found", "event not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "query_failed", "event query unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"code": 0, "message": "success", "data": event})
}

func (handler Handler) now() time.Time {
	if handler.Now != nil {
		return handler.Now().UTC()
	}
	return time.Now().UTC()
}

func parseQuery(request *http.Request, now time.Time) (analytics.EventV2Query, error) {
	values := request.URL.Query()
	to, err := parseTime(values.Get("to"), now)
	if err != nil {
		return analytics.EventV2Query{}, errors.New("invalid to")
	}
	from, err := parseTime(values.Get("from"), to.Add(-24*time.Hour))
	if err != nil {
		return analytics.EventV2Query{}, errors.New("invalid from")
	}
	if to.Before(from) || to.Sub(from) > analytics.MaxEventV2QueryRange {
		return analytics.EventV2Query{}, errors.New("invalid time range")
	}
	limit := analytics.DefaultEventV2QueryLimit
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return analytics.EventV2Query{}, errors.New("invalid limit")
		}
		limit = parsed
	}
	query := analytics.EventV2Query{
		From:        from,
		To:          to,
		Source:      strings.TrimSpace(values.Get("source")),
		EventType:   strings.TrimSpace(values.Get("event_type")),
		Severity:    strings.TrimSpace(values.Get("severity")),
		Stage:       strings.TrimSpace(values.Get("stage")),
		AssetID:     strings.TrimSpace(values.Get("asset_id")),
		TechniqueID: strings.TrimSpace(values.Get("technique_id")),
		Query:       strings.TrimSpace(values.Get("q")),
		Limit:       limit,
	}
	if cursor := strings.TrimSpace(values.Get("cursor")); cursor != "" {
		at, uid, err := analytics.DecodeEventV2Cursor(cursor)
		if err != nil {
			return analytics.EventV2Query{}, errors.New("invalid cursor")
		}
		query.CursorAt = at
		query.CursorUID = uid
	}
	return query, nil
}

func parseTime(value string, fallback time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback.UTC(), nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid time")
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code": status, "error_code": code, "message": message,
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
