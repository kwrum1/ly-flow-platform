package main

import (
	"encoding/json"
	"net/http"

	"github.com/lyflow/ly-flow-platform/server/analytics"
)

type storageMigrationRequest struct {
	Action string                 `json:"action"`
	Phase  analytics.StoragePhase `json:"phase,omitempty"`
}

func storageMigrationHandler(runtime *StorageEventRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if runtime == nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "migration_unavailable", "event migration unavailable")
			return
		}
		if request.Method == http.MethodGet {
			writeStorageMigrationStatus(writer, request, runtime, nil, "")
			return
		}
		if request.Method != http.MethodPost {
			writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var control storageMigrationRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&control); err != nil {
			writeJSONError(writer, http.StatusBadRequest, "invalid_migration_control", "invalid migration control")
			return
		}
		var report *analytics.ReconciliationReport
		checkpoint := ""
		var err error
		switch control.Action {
		case "advance":
			err = runtime.migration.Advance(request.Context(), control.Phase)
		case "rollback":
			err = runtime.migration.Rollback(request.Context())
		case "backfill":
			checkpoint, err = runtime.migration.Backfill(request.Context(), 1000)
		case "reconcile":
			value, reconcileErr := runtime.migration.Reconcile(request.Context())
			report, err = &value, reconcileErr
		case "observe":
		default:
			writeJSONError(writer, http.StatusBadRequest, "invalid_migration_action", "invalid migration action")
			return
		}
		if err != nil {
			writeJSONError(writer, http.StatusConflict, "migration_control_failed", err.Error())
			return
		}
		writeStorageMigrationStatus(writer, request, runtime, report, checkpoint)
	})
}

func writeStorageMigrationStatus(writer http.ResponseWriter, request *http.Request, runtime *StorageEventRuntime, report *analytics.ReconciliationReport, checkpoint string) {
	status, err := runtime.migration.Status(request.Context())
	if err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "migration_status_failed", err.Error())
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(struct {
		Status         analytics.MigrationStatus       `json:"status"`
		Reconciliation *analytics.ReconciliationReport `json:"reconciliation,omitempty"`
		Checkpoint     string                          `json:"checkpoint,omitempty"`
	}{Status: status, Reconciliation: report, Checkpoint: checkpoint})
}
