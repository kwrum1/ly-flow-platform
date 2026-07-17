package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type migrationControlRequest struct {
	Action string                   `json:"action"`
	Phase  contracts.MigrationPhase `json:"phase,omitempty"`
}

type migrationStatusResponse struct {
	Snapshot    contracts.MigrationSnapshot     `json:"snapshot"`
	ReadSource  contracts.ReadSource            `json:"read_source"`
	WriteMode   contracts.WriteMode             `json:"write_mode"`
	Observation contracts.MigrationObservation  `json:"observation"`
	Reconcile   *contracts.ReconciliationReport `json:"reconciliation,omitempty"`
	Retirement  contracts.RetirementStatus      `json:"retirement"`
}

func eventMigrationHandler(runtime *EventMigrationRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if runtime == nil {
			writeJSONError(writer, http.StatusServiceUnavailable, "migration_unavailable", "event migration unavailable")
			return
		}
		if request.Method == http.MethodGet {
			writeMigrationStatus(writer, migrationStatus(runtime, nil, request))
			return
		}
		if request.Method != http.MethodPost {
			writeJSONError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var control migrationControlRequest
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&control); err != nil {
			writeJSONError(writer, http.StatusBadRequest, "invalid_migration_control", "invalid migration control")
			return
		}
		var report *contracts.ReconciliationReport
		var err error
		switch control.Action {
		case "advance":
			if control.Phase == contracts.PhaseRetireLegacy {
				err = runtime.Retire(request.Context(), time.Now().UTC())
			} else {
				err = runtime.Advance(request.Context(), control.Phase)
			}
		case "rollback":
			err = runtime.Rollback(request.Context())
		case "reconcile":
			value, reconcileErr := runtime.Reconcile(request.Context())
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
		writeMigrationStatus(writer, migrationStatus(runtime, report, request))
	})
}

func migrationStatus(runtime *EventMigrationRuntime, report *contracts.ReconciliationReport, request *http.Request) migrationStatusResponse {
	snapshot := runtime.Snapshot()
	state, err := contracts.NewMigrationStateFromSnapshot(snapshot)
	if err != nil {
		return migrationStatusResponse{Snapshot: snapshot, Retirement: contracts.RetirementStatus{Reason: err.Error()}}
	}
	return migrationStatusResponse{Snapshot: snapshot, ReadSource: state.ReadSource(), WriteMode: state.WriteMode(),
		Observation: runtime.Observe(), Reconcile: report,
		Retirement: runtime.RetirementStatus(request.Context(), time.Now().UTC())}
}

func writeMigrationStatus(writer http.ResponseWriter, status migrationStatusResponse) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(status)
}
