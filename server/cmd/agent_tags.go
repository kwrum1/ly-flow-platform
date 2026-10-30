package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const (
	agentTagsMaxCount = 16
	agentTagsMaxLen   = 32
)

var agentTagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// normalizeAgentTags trims, lowercases, validates and deduplicates tags so that
// tag scoped defense schedules match deterministically.
func normalizeAgentTags(raw []string) ([]string, string) {
	if len(raw) > agentTagsMaxCount {
		return nil, "too_many_tags"
	}
	seen := make(map[string]struct{}, len(raw))
	tags := make([]string, 0, len(raw))
	for _, item := range raw {
		tag := strings.ToLower(strings.TrimSpace(item))
		if tag == "" {
			continue
		}
		if len(tag) > agentTagsMaxLen || !agentTagPattern.MatchString(tag) {
			return nil, "invalid_tag"
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, ""
}

func agentTagsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.DBPool == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "database_unavailable", "Database is not available")
			return
		}
		agentID := normalizeAgentID(strings.TrimPrefix(r.URL.Path, "/api/v1/agent/tags/"))
		if agentID == "" {
			writeJSONError(w, http.StatusBadRequest, "agent_id_required", "agent id required")
			return
		}
		switch r.Method {
		case http.MethodGet:
			var tags []string
			if err := cfg.DBPool.QueryRow(r.Context(), `SELECT COALESCE(tags, '{}'::text[]) FROM agents WHERE uuid=$1`, agentID).Scan(&tags); err != nil {
				writeJSONError(w, http.StatusNotFound, "agent_not_found", "agent not found")
				return
			}
			if tags == nil {
				tags = []string{}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"agent_id": agentID, "tags": tags}})
		case http.MethodPut, http.MethodPost:
			var req struct {
				Tags []string `json:"tags"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
				return
			}
			tags, reason := normalizeAgentTags(req.Tags)
			if reason != "" {
				writeJSONError(w, http.StatusBadRequest, reason, "tags must be lowercase [a-z0-9._-], max 16 tags and 32 chars each")
				return
			}
			command, err := cfg.DBPool.Exec(r.Context(), `UPDATE agents SET tags=$2 WHERE uuid=$1`, agentID, tags)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "tag_update_failed", err.Error())
				return
			}
			if command.RowsAffected() == 0 {
				writeJSONError(w, http.StatusNotFound, "agent_not_found", "agent not found")
				return
			}
			log.Printf("agent tags updated: agent=%s tags=%v", agentID, tags)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"agent_id": agentID, "tags": tags}})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}
