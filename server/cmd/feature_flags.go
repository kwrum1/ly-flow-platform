package main

import "strings"

// FeatureFlags holds server-side feature switches for the LyFlow v2 rollout.
// Every flag must default to false so an existing deployment keeps its current
// behavior until the flag is explicitly enabled.
type FeatureFlags struct {
	EventSchemaV2    bool
	QueryV2          bool
	CorrelationV2    bool
	AgentFacade      bool
	ResponseApproval bool
}

// loadFeatureFlags reads feature flags from the environment.
func loadFeatureFlags() FeatureFlags {
	return FeatureFlags{
		EventSchemaV2:    featureBool(getEnv("EVENT_SCHEMA_V2_ENABLED", "false")),
		QueryV2:          featureBool(getEnv("QUERY_V2_ENABLED", "false")),
		CorrelationV2:    featureBool(getEnv("CORRELATION_V2_ENABLED", "false")),
		AgentFacade:      featureBool(getEnv("AGENT_FACADE_ENABLED", "false")),
		ResponseApproval: featureBool(getEnv("RESPONSE_APPROVAL_ENABLED", "false")),
	}
}

// featureBool accepts common human spellings used in deployment files while
// keeping the shared toBool helper unchanged for existing configuration.
func featureBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// AnyEnabled reports whether at least one v2 feature is active. It is useful
// for startup logs and health diagnostics.
func (f FeatureFlags) AnyEnabled() bool {
	return f.EventSchemaV2 || f.QueryV2 || f.CorrelationV2 || f.AgentFacade || f.ResponseApproval
}
