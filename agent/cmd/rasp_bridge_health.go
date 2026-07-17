package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func (bridge *raspBridgeRuntime) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !bridge.authenticate(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if err := encodeRASPBridgeJSON(w, http.StatusOK, bridge.Health()); err != nil {
			bridge.setLastError(err)
		}
	case http.MethodPost:
		bridge.acceptControlHealth(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (bridge *raspBridgeRuntime) acceptControlHealth(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(bridge.limits.ReadBytes))
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var health runtimeControlHealthSnapshot
	if err := decoder.Decode(&health); err != nil {
		http.Error(w, "invalid control health", http.StatusBadRequest)
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid control health", http.StatusBadRequest)
		return
	}
	if err := validateRASPControlHealth(health); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := bridge.agent.propagateControlHealth(health); err != nil {
		bridge.setLastError(err)
		http.Error(w, "control-health publication failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func validateRASPControlHealth(health runtimeControlHealthSnapshot) error {
	if health.SchemaVersion != controlHealthSchemaVersion || health.EventType != controlHealthEventType {
		return fmt.Errorf("control health schema invalid")
	}
	if health.Runtime != "python-rasp" && health.Runtime != "java-rasp" && health.Runtime != "agent-rasp-bridge" {
		return fmt.Errorf("control health runtime invalid")
	}
	if health.Status != controlHealthHealthy && health.Status != controlHealthDegraded {
		return fmt.Errorf("control health status invalid")
	}
	if health.Publication.Status != controlHealthHealthy && health.Publication.Status != controlHealthDegraded {
		return fmt.Errorf("control health publication invalid")
	}
	if health.WatchdogAt.IsZero() || health.Limits.QueueCapacity <= 0 || health.Limits.ReadBytes <= 0 || health.Limits.CPUBudgetMS <= 0 || health.Limits.MemoryBytes <= 0 || health.Limits.RestartBudget <= 0 {
		return fmt.Errorf("control health limits invalid")
	}
	return nil
}
