package eventinventory

import (
	"sort"
	"strings"
)

func shouldSkipDirectory(path string) bool {
	if path == ".git" || path == "frontend" || path == "third_party" || path == ".omo" {
		return true
	}
	return path == "pkg/eventinventory" || path == "pkg/transportreliability" || strings.HasPrefix(path, "pkg/cmd/generate-event-inventory")
}

func isContractType(name string) bool {
	switch name {
	case "TelemetryEnvelope", "ComponentAlert", "CanonicalSecurityEvent", "MigrationState", "MigrationSnapshot", "MigrationObservation", "ReconciliationReport", "GovernanceMetadata", "UnifiedEvent", "CanonicalEventV2", "SecurityEvent":
		return true
	default:
		return false
	}
}

func isStreamName(value string) bool {
	for _, prefix := range []string{"telemetry:", "alerts:", "events:", "deadletter:", "flows:", "sessions:"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return value == "component_alerts:v2" || value == "security_events:v1"
}

func hasFunctionPrefix(functions []string, prefixes ...string) bool {
	for _, function := range functions {
		lower := strings.ToLower(function)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	}
	return false
}

func hasFunctionFragment(functions []string, fragments ...string) bool {
	for _, function := range functions {
		lower := strings.ToLower(function)
		for _, fragment := range fragments {
			if strings.Contains(lower, fragment) {
				return true
			}
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
