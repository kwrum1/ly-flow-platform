package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/lyflow/ly-flow-platform/server/response"
)

func responseAutomationHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.ResponseActions == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "response_automation_unavailable", "response automation unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeAutomation(w, cfg)
		case http.MethodPut, http.MethodPost:
			var next response.AutomationPolicy
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&next); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_response_automation", "Invalid response automation policy")
				return
			}
			if _, err := cfg.ResponseActions.UpdateAutomation(next); err != nil {
				writeJSONError(w, http.StatusBadRequest, "response_automation_rejected", err.Error())
				return
			}
			writeAutomation(w, cfg)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func writeAutomation(w http.ResponseWriter, cfg *Config) {
	policy := cfg.ResponseActions.Automation()
	now := time.Now()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"enabled":                    policy.Enabled,
			"window_start_hour":          policy.WindowStartHour,
			"window_end_hour":            policy.WindowEndHour,
			"require_different_approver": policy.RequireDifferentApprover,
			"approval_ttl_minutes":       policy.ApprovalTTLMinutes,
			"timezone":                   "Asia/Shanghai",
			"active":                     cfg.ResponseActions.AutomationActive(now),
			"scope":                      "L2 actions only; L3 always requires a second approver",
		},
	})
}
