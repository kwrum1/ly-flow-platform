package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
)

// raspPolicyStatusHandler exposes the signed policy lifecycle. It never invents
// an enforcement state: canary policies are reported as dry-run, and only an
// active block version with the operator opt-in can be enforcing.
func raspPolicyStatusHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if cfg.RASPPolicy == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "rasp_policy_unavailable", "RASP policy lifecycle unavailable")
			return
		}
		latest, active, err := cfg.RASPPolicy.Snapshot(r.Context())
		if err != nil && !errors.Is(err, agentpolicy.ErrNotFound) {
			writeJSONError(w, http.StatusInternalServerError, "rasp_policy_load_failed", err.Error())
			return
		}
		payload := map[string]interface{}{
			"allow_production_block": cfg.RASPPolicy.ProductionBlockAllowed(),
			"latest":                 nil,
			"active":                 nil,
			"enforcing":              false,
			"dry_run":                map[string]interface{}{"would_block": 0, "blocked": 0},
		}
		if latest.Envelope.Policy.Version != 0 {
			row := persistedPolicyRow(latest)
			payload["latest"] = row
			payload["dry_run"] = raspDryRunCounts(r.Context(), cfg, latest.Envelope.Policy.Version)
			if latest.State == agentpolicy.StateCanary {
				payload["canary"] = row
			}
		}
		if active.Envelope.Policy.Version != 0 {
			row := persistedPolicyRow(active)
			payload["active"] = row
			enforcing := active.Envelope.Policy.Mode == agentpolicy.ModeBlock &&
				active.State == agentpolicy.StateActive && cfg.RASPPolicy.ProductionBlockAllowed()
			payload["enforcing"] = enforcing
		}
		payload["agents"] = raspPolicyAgentStates(r.Context(), cfg)
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": payload})
	}
}

func raspPolicyCanaryHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if cfg.RASPPolicy == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "rasp_policy_unavailable", "RASP policy lifecycle unavailable")
			return
		}
		var request struct {
			Owner                     string   `json:"owner"`
			AgentIDs                  []string `json:"agent_ids"`
			Languages                 []string `json:"languages"`
			RequiredACKs              int      `json:"required_acks"`
			ReplayMinSamples          int      `json:"replay_min_samples"`
			ReplayMaxFalsePositive    float64  `json:"replay_max_false_positive_rate"`
			MaxBlocksPerMinute        int      `json:"max_blocks_per_minute"`
			ExpiresInSeconds          int      `json:"expires_in_seconds"`
			RollbackWindowInSeconds   int      `json:"rollback_window_seconds"`
			MaxEventsPerSecond        int      `json:"max_events_per_second"`
			CanaryObservationWindowMS int      `json:"canary_observation_window_ms"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body")
			return
		}
		latest, active, err := cfg.RASPPolicy.Snapshot(r.Context())
		if err != nil && !errors.Is(err, agentpolicy.ErrNotFound) {
			writeJSONError(w, http.StatusInternalServerError, "rasp_policy_load_failed", err.Error())
			return
		}
		if latest.State == agentpolicy.StateCanary && latest.Envelope.Policy.ExpiresAt.After(time.Now().UTC()) {
			writeJSONError(w, http.StatusConflict, "rasp_canary_in_progress", "a canary policy is already in progress")
			return
		}
		base := active.Envelope.Policy
		if base.Version == 0 || base.Mode != agentpolicy.ModeMonitor {
			writeJSONError(w, http.StatusConflict, "rasp_monitor_baseline_required", "an active monitor policy is required before a block canary")
			return
		}
		version := latest.Envelope.Policy.Version + 1
		if active.Envelope.Policy.Version >= version {
			version = active.Envelope.Policy.Version + 1
		}
		now := time.Now().UTC()
		policy := base
		policy.Version = version
		policy.Mode = agentpolicy.ModeBlock
		policy.FailBehavior = agentpolicy.FailMonitor
		policy.AuditLink = "audit://rasp-policy/block-canary/" + strconv.FormatUint(version, 10)
		if strings.TrimSpace(request.Owner) != "" {
			policy.Owner = strings.TrimSpace(request.Owner)
		}
		if len(request.AgentIDs) > 0 {
			policy.Selectors.AgentIDs = request.AgentIDs
		}
		if len(request.Languages) > 0 {
			languages := make([]agentpolicy.Language, 0, len(request.Languages))
			for _, value := range request.Languages {
				languages = append(languages, agentpolicy.Language(strings.ToLower(strings.TrimSpace(value))))
			}
			policy.Selectors.Languages = languages
		}
		policy.ExpiresAt = now.Add(secondsOrDefault(request.ExpiresInSeconds, 24*60*60))
		policy.Rollback = agentpolicy.RollbackPolicy{
			TargetVersion: active.Envelope.Policy.Version,
			Deadline:      now.Add(secondsOrDefault(request.RollbackWindowInSeconds, 2*60*60)),
		}
		policy.Canary = agentpolicy.CanaryPolicy{RequiredACKs: intOrDefault(request.RequiredACKs, 1)}
		policy.Limits.ReplayMinSamples = intOrDefault(request.ReplayMinSamples, 1000)
		if request.ReplayMaxFalsePositive > 0 {
			policy.Limits.ReplayMaxFalsePositiveRate = request.ReplayMaxFalsePositive
		}
		if policy.Limits.ReplayMaxFalsePositiveRate <= 0 {
			policy.Limits.ReplayMaxFalsePositiveRate = 0.01
		}
		policy.Limits.MaxBlocksPerMinute = intOrDefault(request.MaxBlocksPerMinute, 60)
		policy.Limits.MaxEventsPerSecond = intOrDefault(request.MaxEventsPerSecond, base.Limits.MaxEventsPerSecond)
		if policy.Limits.MaxEventsPerSecond <= 0 {
			policy.Limits.MaxEventsPerSecond = 100
		}
		envelope, err := cfg.RASPPolicy.Create(r.Context(), policy)
		if err != nil {
			writeJSONError(w, http.StatusConflict, "rasp_canary_create_rejected", err.Error())
			return
		}
		if err := cfg.RASPPolicy.StartCanary(r.Context(), policy.Version); err != nil {
			writeJSONError(w, http.StatusConflict, "rasp_canary_start_rejected", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{
				"version": policy.Version, "mode": policy.Mode, "state": agentpolicy.StateCanary,
				"enforcing": false, "envelope": envelope,
			},
		})
	}
}

// raspPolicyActionHandler serves /api/v1/rasp/policy/actions/{version}/{action}.
func raspPolicyActionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if cfg.RASPPolicy == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "rasp_policy_unavailable", "RASP policy lifecycle unavailable")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/rasp/policy/actions/")
		if path == "emergency-stop" {
			raspEmergencyStop(w, r, cfg)
			return
		}
		versionText, action, found := strings.Cut(path, "/")
		version, err := strconv.ParseUint(versionText, 10, 64)
		if !found || err != nil || version == 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_policy_version", "a valid policy version and action are required")
			return
		}
		switch action {
		case "complete":
			var request struct {
				Succeeded         bool    `json:"succeeded"`
				FailureReason     string  `json:"failure_reason"`
				SampleCount       int     `json:"sample_count"`
				FalsePositiveRate float64 `json:"false_positive_rate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON body")
				return
			}
			observation := agentpolicy.CanaryObservation{
				Succeeded: request.Succeeded, FailureReason: strings.TrimSpace(request.FailureReason),
			}
			// Metrics are required for a successful canary; zero samples never
			// prove anything and must not be reported as a pass.
			if request.Succeeded {
				if request.SampleCount <= 0 {
					writeJSONError(w, http.StatusUnprocessableEntity, "rasp_replay_metrics_required", "sample_count must be greater than zero")
					return
				}
				observation.Replay = &agentpolicy.ReplayMetrics{
					SampleCount: request.SampleCount, FalsePositiveRate: request.FalsePositiveRate,
				}
			}
			if err := cfg.RASPPolicy.CompleteCanary(r.Context(), version, observation); err != nil {
				writePolicyLifecycleError(w, err)
				return
			}
		case "promote":
			if err := cfg.RASPPolicy.Promote(r.Context(), version); err != nil {
				writePolicyLifecycleError(w, err)
				return
			}
		case "rollback":
			if err := cfg.RASPPolicy.Rollback(r.Context(), version); err != nil {
				writePolicyLifecycleError(w, err)
				return
			}
		default:
			writeJSONError(w, http.StatusNotFound, "unknown_policy_action", "unknown policy action")
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{"version": version, "action": action},
		})
	}
}

func raspEmergencyStop(w http.ResponseWriter, r *http.Request, cfg *Config) {
	latest, active, err := cfg.RASPPolicy.Snapshot(r.Context())
	if err != nil && !errors.Is(err, agentpolicy.ErrNotFound) {
		writeJSONError(w, http.StatusInternalServerError, "rasp_policy_load_failed", err.Error())
		return
	}
	candidate := latest
	if active.Envelope.Policy.Mode == agentpolicy.ModeBlock {
		candidate = active
	}
	if candidate.Envelope.Policy.Mode != agentpolicy.ModeBlock {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{"stopped": false, "reason": "no_block_policy"},
		})
		return
	}
	if err := cfg.RASPPolicy.Rollback(r.Context(), candidate.Envelope.Policy.Version); err != nil {
		writePolicyLifecycleError(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"stopped": true, "version": candidate.Envelope.Policy.Version},
	})
}

func writePolicyLifecycleError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	code := "rasp_policy_transition_rejected"
	switch {
	case errors.Is(err, agentpolicy.ErrProductionBlockDisabled):
		code = "rasp_block_not_allowed"
	case errors.Is(err, agentpolicy.ErrReplayMetricsRequired):
		code = "rasp_replay_metrics_required"
	case errors.Is(err, agentpolicy.ErrMissingACK):
		code = "rasp_ack_required"
	case errors.Is(err, agentpolicy.ErrCanaryFailed):
		code = "rasp_canary_failed"
	case errors.Is(err, agentpolicy.ErrOwnerRequired):
		code = "rasp_owner_required"
	case errors.Is(err, agentpolicy.ErrRollbackRequired):
		code = "rasp_rollback_required"
	case errors.Is(err, agentpolicy.ErrInvalidTransition):
		code = "rasp_invalid_transition"
	default:
		status = http.StatusInternalServerError
		code = "rasp_policy_transition_failed"
	}
	writeJSONError(w, status, code, err.Error())
}

func persistedPolicyRow(stored agentpolicy.PersistedPolicy) map[string]interface{} {
	policy := stored.Envelope.Policy
	row := map[string]interface{}{
		"version":       policy.Version,
		"id":            policy.ID,
		"mode":          policy.Mode,
		"state":         stored.State,
		"owner":         policy.Owner,
		"expires_at":    policy.ExpiresAt,
		"fail_behavior": policy.FailBehavior,
		"limits": map[string]interface{}{
			"max_events_per_second":          policy.Limits.MaxEventsPerSecond,
			"max_blocks_per_minute":          policy.Limits.MaxBlocksPerMinute,
			"replay_min_samples":             policy.Limits.ReplayMinSamples,
			"replay_max_false_positive_rate": policy.Limits.ReplayMaxFalsePositiveRate,
		},
		"canary":     policy.Canary,
		"rollback":   policy.Rollback,
		"updated_at": stored.UpdatedAt,
	}
	if stored.Canary != nil {
		row["canary_observation"] = stored.Canary
	}
	return row
}

func raspDryRunCounts(ctx context.Context, cfg *Config, version uint64) map[string]interface{} {
	counts := map[string]interface{}{"would_block": 0, "blocked": 0}
	if cfg == nil || cfg.DBPool == nil {
		return counts
	}
	row := cfg.DBPool.QueryRow(ctx, `SELECT
		COUNT(*) FILTER (WHERE lower(coalesce(raw_event->>'would_block', raw_event->'details'->>'would_block','false')) IN ('true','1')),
		COUNT(*) FILTER (WHERE lower(coalesce(raw_event->>'blocked', raw_event->'details'->>'blocked','false')) IN ('true','1'))
		FROM threat_events WHERE category='rasp' AND coalesce(raw_event->>'policy_version', raw_event->'details'->>'policy_version')=$1`,
		strconv.FormatUint(version, 10))
	var wouldBlock, blocked int64
	if err := row.Scan(&wouldBlock, &blocked); err != nil {
		counts["error"] = err.Error()
		return counts
	}
	counts["would_block"] = wouldBlock
	counts["blocked"] = blocked
	return counts
}

func raspPolicyAgentStates(ctx context.Context, cfg *Config) []map[string]interface{} {
	items := make([]map[string]interface{}, 0)
	if cfg == nil {
		return items
	}
	agents, err := loadRASPProtectionAgents(cfg)
	if err != nil {
		return items
	}
	for _, agent := range agents {
		item := map[string]interface{}{
			"agent_id": xdrPickString(agent, "agent_id"),
			"mode":     xdrPickString(agent, "mode"),
			"enabled":  agent["enabled"],
			"state":    xdrPickString(agent, "state"),
		}
		items = append(items, item)
	}
	return items
}

func secondsOrDefault(value, fallback int) time.Duration {
	if value <= 0 {
		value = fallback
	}
	return time.Duration(value) * time.Second
}

func intOrDefault(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}
