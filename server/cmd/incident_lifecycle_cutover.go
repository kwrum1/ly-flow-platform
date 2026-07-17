package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
)

const legacyIncidentStatusSource = "server/cmd.incidentStatusStore sync.Map via PUT /api/v1/incidents/{id}/status"

type capturedLegacyIncidentStatus struct {
	status incidentlifecycle.LegacyStatus
}

type incidentLegacyCheckpointer interface {
	CheckpointLegacySnapshot(context.Context, []incidentlifecycle.LegacyStatus, string) (incidentlifecycle.SnapshotReport, error)
}

func checkpointLegacyIncidentStatuses(ctx context.Context, cfg *Config) (incidentlifecycle.SnapshotReport, error) {
	captured := captureLegacyIncidentStatuses()
	statuses := make([]incidentlifecycle.LegacyStatus, 0, len(captured))
	for _, entry := range captured {
		statuses = append(statuses, entry.status)
	}
	if cfg == nil || cfg.IncidentCheckpoint == nil {
		return degradedLegacyCheckpointReport(statuses, incidentlifecycle.SnapshotReport{}), fmt.Errorf("incident lifecycle checkpoint store unavailable")
	}
	report, err := cfg.IncidentCheckpoint.CheckpointLegacySnapshot(ctx, statuses, legacyIncidentStatusSource)
	if err != nil {
		report = degradedLegacyCheckpointReport(statuses, report)
	}
	if cfg.IncidentSnapshot == nil {
		cfg.IncidentSnapshot = &incidentSnapshotState{}
	}
	cfg.IncidentSnapshot.report = report
	cfg.IncidentSnapshot.err = err
	return report, err
}

func checkpointIncidentLifecycleOnShutdown(ctx context.Context, cfg *Config) (incidentlifecycle.SnapshotReport, error) {
	report, err := checkpointLegacyIncidentStatuses(ctx, cfg)
	if err != nil {
		return report, err
	}
	log.Printf("incident lifecycle shutdown checkpoint: captured=%d checksum=%s captured_at=%s unrecoverable=%d cutover_marked=%v",
		report.Captured, report.SnapshotChecksum, report.SnapshotCapturedAt.Format(time.RFC3339Nano), report.Unrecoverable.Total(), report.CutoverMarked)
	return report, nil
}

func degradedLegacyCheckpointReport(statuses []incidentlifecycle.LegacyStatus, report incidentlifecycle.SnapshotReport) incidentlifecycle.SnapshotReport {
	report.Source = legacyIncidentStatusSource
	report.Captured = len(statuses)
	report.ImportableFields = []string{"status"}
	report.CutoverMarked = false
	report.Unrecoverable.Status = len(statuses)
	report.Unrecoverable.Assignee = len(statuses)
	report.Unrecoverable.Suppression = len(statuses)
	report.Unrecoverable.TransitionHistory = 0
	historyPersisted := len(report.UnrecoverableHistory) > 0
	for _, status := range statuses {
		report.UnrecoverableDetails = append(report.UnrecoverableDetails, status.IncidentID+": status checkpoint unavailable; checkpoint persistence failed")
		if status.Status != incidentlifecycle.StatusOpen {
			report.Unrecoverable.TransitionHistory++
			if !historyPersisted {
				report.UnrecoverableHistory = append(report.UnrecoverableHistory, status.IncidentID+": prior in-memory transition history unavailable")
			}
		}
	}
	return report
}

func incidentLifecycleCheckpointHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if cfg == nil || !cfg.IncidentLegacyMode {
			writeJSONError(w, http.StatusConflict, "incident_checkpoint_inactive", "legacy incident checkpoint mode is inactive")
			return
		}
		report, err := checkpointLegacyIncidentStatuses(r.Context(), cfg)
		status := http.StatusOK
		message := "checkpoint persisted"
		if err != nil {
			status = http.StatusServiceUnavailable
			message = err.Error()
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": status, "message": message, "data": report})
	}
}

func captureLegacyIncidentStatuses() []capturedLegacyIncidentStatus {
	captured := make([]capturedLegacyIncidentStatus, 0)
	incidentStatusStore.Range(func(key, value interface{}) bool {
		captured = append(captured, capturedLegacyIncidentStatus{status: incidentlifecycle.LegacyStatus{
			IncidentID: strings.TrimSpace(fmt.Sprint(key)),
			Status:     incidentlifecycle.Status(strings.TrimSpace(fmt.Sprint(value))),
		}})
		return true
	})
	return captured
}

func clearLegacyIncidentStatuses() {
	incidentStatusStore.Range(func(key, _ interface{}) bool {
		incidentStatusStore.Delete(key)
		return true
	})
}

func legacyIncidentStatusHandler(cfg *Config, id string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.Incidents != nil {
			incidentMutationHandler(cfg, id, "status").ServeHTTP(w, r)
			return
		}
		var request struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
			return
		}
		status := strings.TrimSpace(request.Status)
		if status == "" {
			writeJSONError(w, http.StatusBadRequest, "status_required", "status required")
			return
		}
		incidentStatusStore.Store(id, status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{
			"id": id, "status": status, "status_label": incidentStatusLabel(status),
		}})
	}
}
