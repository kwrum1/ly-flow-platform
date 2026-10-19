package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/evidence"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

const maxEvidenceBody = 64 << 20

type evidenceBundleRequest struct {
	IncidentID  string   `json:"incident_id"`
	AgentID     string   `json:"agent_id"`
	EventUIDs   []string `json:"event_uids"`
	ArtifactIDs []string `json:"artifact_ids"`
	Note        string   `json:"note"`
}

func evidenceHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.Evidence == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "evidence_unavailable", "evidence store unavailable")
			return
		}
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/evidence"), "/")
		switch {
		case path == "artifacts" && r.Method == http.MethodPost:
			createEvidenceArtifact(w, r, cfg)
		case strings.HasPrefix(path, "artifacts/") && r.Method == http.MethodGet:
			getEvidenceArtifact(w, r, cfg, strings.TrimPrefix(path, "artifacts/"))
		case path == "bundles" && r.Method == http.MethodGet:
			listEvidenceBundles(w, cfg, r)
		case path == "bundles" && r.Method == http.MethodPost:
			createEvidenceBundle(w, r, cfg)
		case strings.HasPrefix(path, "bundles/") && strings.HasSuffix(path, "/download") && r.Method == http.MethodGet:
			downloadEvidenceBundle(w, r, cfg, strings.TrimSuffix(strings.TrimPrefix(path, "bundles/"), "/download"))
		case strings.HasPrefix(path, "bundles/") && r.Method == http.MethodGet:
			getEvidenceBundle(w, r, cfg, strings.TrimPrefix(path, "bundles/"))
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func createEvidenceArtifact(w http.ResponseWriter, r *http.Request, cfg *Config) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEvidenceBody))
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "evidence_artifact_too_large", err.Error())
		return
	}
	artifact, err := cfg.Evidence.PutArtifact(r.Header.Get("X-Lyflow-Artifact-Name"), r.Header.Get("Content-Type"), data)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "evidence_artifact_rejected", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": artifact})
}

func getEvidenceArtifact(w http.ResponseWriter, r *http.Request, cfg *Config, id string) {
	artifact, data, err := cfg.Evidence.GetArtifact(strings.TrimSpace(id))
	if errors.Is(err, evidence.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "evidence_artifact_not_found", "evidence artifact not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_artifact_read_failed", err.Error())
		return
	}
	mediaType := artifact.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", artifact.Name))
	w.Header().Set("X-Lyflow-Evidence-SHA256", artifact.SHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func listEvidenceBundles(w http.ResponseWriter, cfg *Config, r *http.Request) {
	items, err := cfg.Evidence.ListBundles(toInt(r.URL.Query().Get("limit")))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_bundles_read_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items)}})
}

func createEvidenceBundle(w http.ResponseWriter, r *http.Request, cfg *Config) {
	var request evidenceBundleRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEvidenceBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_evidence_bundle", "Invalid evidence bundle request")
		return
	}
	if len(request.EventUIDs) == 0 && len(request.ArtifactIDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "evidence_bundle_empty", "At least one event_uid or artifact_id is required")
		return
	}
	payload := map[string]interface{}{
		"schema": "lyflow.evidence.bundle.v1", "incident_id": request.IncidentID,
		"agent_id": request.AgentID, "note": request.Note,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		"created_by": fmt.Sprintf("user:%d", auth.GetUserIDFromContext(r.Context())),
	}
	events := make([]interface{}, 0, len(request.EventUIDs))
	if cfg.EventStorage == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "evidence_events_unavailable", "event storage unavailable")
		return
	}
	for _, eventUID := range request.EventUIDs {
		eventUID = strings.TrimSpace(eventUID)
		if eventUID == "" {
			continue
		}
		event, err := cfg.EventStorage.GetEventV2(r.Context(), eventUID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "evidence_event_not_found", "event not found: "+eventUID)
			return
		}
		events = append(events, event)
	}
	artifacts := make([]interface{}, 0, len(request.ArtifactIDs))
	for _, artifactID := range request.ArtifactIDs {
		artifactID = strings.TrimSpace(artifactID)
		if artifactID == "" {
			continue
		}
		artifact, _, err := cfg.Evidence.GetArtifact(artifactID)
		if errors.Is(err, evidence.ErrNotFound) {
			writeJSONError(w, http.StatusBadRequest, "evidence_artifact_not_found", "artifact not found: "+artifactID)
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "evidence_artifact_read_failed", err.Error())
			return
		}
		artifacts = append(artifacts, artifact)
	}
	payload["events"] = events
	payload["artifacts"] = artifacts
	encoded, err := json.Marshal(payload)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_bundle_encode_failed", err.Error())
		return
	}
	bundle, err := cfg.Evidence.PutBundle(evidence.Bundle{
		IncidentID: request.IncidentID, AgentID: request.AgentID,
		CreatedBy: fmt.Sprintf("user:%d", auth.GetUserIDFromContext(r.Context())),
		EventUIDs: request.EventUIDs, ArtifactIDs: request.ArtifactIDs,
	}, encoded)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_bundle_write_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": bundle})
}

func getEvidenceBundle(w http.ResponseWriter, r *http.Request, cfg *Config, id string) {
	bundle, _, err := cfg.Evidence.GetBundle(strings.TrimSpace(id))
	if errors.Is(err, evidence.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "evidence_bundle_not_found", "evidence bundle not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_bundle_read_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": bundle})
}

func downloadEvidenceBundle(w http.ResponseWriter, r *http.Request, cfg *Config, id string) {
	bundle, data, err := cfg.Evidence.GetBundle(strings.TrimSpace(id))
	if errors.Is(err, evidence.ErrNotFound) {
		writeJSONError(w, http.StatusNotFound, "evidence_bundle_not_found", "evidence bundle not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "evidence_bundle_read_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", bundle.MediaType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", bundle.ID+".json"))
	w.Header().Set("X-Lyflow-Evidence-SHA256", bundle.SHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
