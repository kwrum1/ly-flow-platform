package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
)

const defaultIngestionRatePerMinute = 60_000

type IngestionWriter interface {
	Write(context.Context, string, map[string]interface{}) error
}

func newIngestionAuthenticator(cfg *Config, audit ingestionauth.Audit) *ingestionauth.Authenticator {
	rateLimit := toInt(getEnv("AGENT_INGESTION_RATE_PER_MINUTE", "60000"))
	if rateLimit <= 0 {
		rateLimit = defaultIngestionRatePerMinute
	}
	return ingestionauth.New(cfg.AgentIdentity, audit, time.Now, rateLimit, time.Minute)
}

func authenticateIngestion(writer http.ResponseWriter, request *http.Request, cfg *Config, surface string) (ingestionauth.Principal, bool) {
	if cfg == nil || cfg.IngestionAuth == nil {
		writeJSONError(writer, http.StatusUnauthorized, "agent_auth_required", "valid Agent credential required")
		return ingestionauth.Principal{}, false
	}
	principal, err := cfg.IngestionAuth.HTTPPrincipal(request, surface)
	switch {
	case ingestionauth.IsAuditUnavailable(err):
		writeJSONError(writer, http.StatusServiceUnavailable, "ingestion_audit_unavailable", "Agent ingestion lifecycle audit unavailable")
		return ingestionauth.Principal{}, false
	case ingestionauth.IsRateLimited(err):
		writeJSONError(writer, http.StatusTooManyRequests, "ingestion_rate_limited", "Agent ingestion rate limit exceeded")
		return ingestionauth.Principal{}, false
	case err != nil:
		writeJSONError(writer, http.StatusUnauthorized, "agent_auth_required", "valid Agent credential required")
		return ingestionauth.Principal{}, false
	default:
		return principal, true
	}
}

func decodeIngestionJSON(writer http.ResponseWriter, request *http.Request, cfg *Config, principal ingestionauth.Principal, surface string, destination interface{}) bool {
	err := ingestionauth.DecodeJSON(writer, request, destination)
	if err == nil {
		return true
	}
	status := http.StatusBadRequest
	code := "invalid_json"
	message := "Invalid JSON"
	if ingestionauth.IsBodyTooLarge(err) {
		status = http.StatusRequestEntityTooLarge
		code = "ingestion_body_too_large"
		message = "Agent ingestion body exceeds limit"
	}
	if !recordIngestionRejection(writer, request, cfg, principal, surface, ingestionauth.OutcomeRejected, err.Error()) {
		return false
	}
	writeJSONError(writer, status, code, message)
	return false
}

func bindIngestionPrincipal(writer http.ResponseWriter, request *http.Request, cfg *Config, principal ingestionauth.Principal, surface, payloadAgentID string) (string, bool) {
	agentID, err := principal.BindPayloadAgentID(payloadAgentID)
	if err == nil {
		return agentID, true
	}
	if errors.Is(err, ingestionauth.ErrIdentityMismatch) {
		if !recordIngestionRejection(writer, request, cfg, principal, surface, ingestionauth.OutcomeIdentityMismatch, ingestionauth.ErrIdentityMismatch.Error()) {
			return "", false
		}
		writeJSONError(writer, http.StatusForbidden, "agent_identity_mismatch", "payload Agent identity conflicts with authenticated principal")
		return "", false
	}
	if !recordIngestionRejection(writer, request, cfg, principal, surface, ingestionauth.OutcomeRejected, err.Error()) {
		return "", false
	}
	writeJSONError(writer, http.StatusBadRequest, "invalid_agent_identity", "invalid Agent identity")
	return "", false
}

func recordIngestionRejection(writer http.ResponseWriter, request *http.Request, cfg *Config, principal ingestionauth.Principal, surface, outcome, reason string) bool {
	if err := cfg.IngestionAuth.Record(request.Context(), principal, surface, outcome, reason); err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "ingestion_audit_unavailable", "Agent ingestion lifecycle audit unavailable")
		return false
	}
	return true
}

func ingestionWriterAvailable(cfg *Config) bool {
	return cfg != nil && (cfg.IngestionWriter != nil || cfg.TransportProducer != nil)
}

func writeIngestionStream(ctx context.Context, cfg *Config, stream string, values map[string]interface{}) error {
	if cfg == nil {
		return errors.New("ingestion writer unavailable")
	}
	if cfg.IngestionWriter != nil {
		return cfg.IngestionWriter.Write(ctx, stream, values)
	}
	if cfg.TransportProducer == nil {
		return errors.New("ingestion writer unavailable")
	}
	return cfg.TransportProducer.PublishAuto(ctx, stream, values)
}

func acceptIngestion(writer http.ResponseWriter, request *http.Request, cfg *Config, principal ingestionauth.Principal, surface string) bool {
	if err := cfg.IngestionAuth.Record(request.Context(), principal, surface, ingestionauth.OutcomeAccepted, ""); err != nil {
		writeJSONError(writer, http.StatusServiceUnavailable, "ingestion_audit_unavailable", "Agent ingestion lifecycle audit unavailable")
		return false
	}
	return true
}
