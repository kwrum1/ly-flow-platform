package main

import "strings"

var ArchitectureRouteSnapshot = buildRouteRegistry()

func buildRouteRegistry() []RouteSpec {
	public := map[string]bool{
		"/api/v1/health":     true,
		"/api/v1/auth/login": true,
	}
	adminOnly := map[string]bool{
		"/api/v1/admin/incident-lifecycle/checkpoint": true,
		"/api/v1/event-migration":                     true,
		"/api/v1/auth/register":                       true,
		"/api/v1/auth/users":                          true,
		"/api/v1/auth/users/":                         true,
		"/api/v1/auth/users/password":                 true,
		"/api/v1/agent/identity":                      true,
		"/api/v1/debug/components":                    true,
		"/api/v1/rule-platform/active-bundle":         true,
		"/api/v1/rule-platform/compile-preview":       true,
		"/api/v1/rule-platform/rollback":              true,
		"/api/v1/rule-platform/sources":               true,
		"/api/v1/rule-platform/sync":                  true,
		"/api/v1/rules":                               true,
		"/api/v1/rules/items/":                        true,
		"/api/v1/rules/score-weights":                 true,
		"/api/v1/rules/sources":                       true,
		"/api/v1/rules/sources/":                      true,
		"/api/v1/rules/subscription":                  true,
		"/api/v1/rules/update":                        true,
		"/api/v1/rules/test":                          true,
		"/api/v1/engine-rules":                        true,
		"/api/v1/engine-rules/update":                 true,
		"/api/v1/rasp/rules":                          true,
	}
	agentCredential := map[string]bool{
		"/api/v1/agent/enroll":          true,
		"/api/v1/agent/heartbeat":       true,
		"/api/v1/agent/config":          true,
		"/api/v1/agent/traffic-event":   true,
		"/api/v1/agent/task-result":     true,
		"/api/v1/agent/component-alert": true,
		"/api/v1/agent/runtime-event":   true,
		"/api/v1/agent/realtime":        true,
		"/api/v1/rasp/event":            true,
	}
	paths := []string{
		"/", "/api/v1/health", "/api/v1/public/situation/global", "/api/v1/stats", "/api/v1/events",
		"/api/v1/security-events", "/api/v1/security-events/", "/api/v1/event-migration", "/api/v1/admin/incident-lifecycle/checkpoint",
		"/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/bootstrap-token", "/api/v1/auth/logout",
		"/api/v1/auth/profile", "/api/v1/auth/change-password", "/api/v1/auth/users", "/api/v1/auth/users/password", "/api/v1/auth/users/",
		"/api/v1/rules", "/api/v1/rules/inventory", "/api/v1/rules/reports", "/api/v1/rules/quarantine",
		"/api/v1/rules/score-weights", "/api/v1/rules/items/", "/api/v1/rules/sources/", "/api/v1/rules/sources",
		"/api/v1/rule-platform/sources", "/api/v1/rule-platform/bundles", "/api/v1/rule-platform/sync",
		"/api/v1/rule-platform/compile-preview", "/api/v1/rule-platform/versions", "/api/v1/rule-platform/rollback",
		"/api/v1/rule-platform/active-bundle", "/api/v1/response/candidates", "/api/v1/response/policy",
		"/api/v1/response/advisories", "/api/v1/response/advisories/",
		"/api/v1/debug/components", "/api/v1/rules/subscription", "/api/v1/rules/categories", "/api/v1/rules/update",
		"/api/v1/rules/stats", "/api/v1/rules/test", "/api/v1/xdr/stats", "/api/v1/xdr/events", "/api/v1/xdr/sources",
		"/api/v1/xdr/top-events", "/api/v1/xdr/chains", "/api/v1/xdr/posture", "/api/v1/xdr/log",
		"/api/v1/unified/stats", "/api/v1/unified/events", "/api/v1/unified/events/search", "/api/v1/engine-health",
		"/api/v1/engine-runtime/status", "/api/v1/engine-rules", "/api/v1/engine-rules/update", "/api/v1/threats/",
		"/api/v1/component-alerts/", "/api/v1/component-alerts", "/api/v1/traffic/threats", "/api/v1/traffic/flows",
		"/api/v1/traffic/sessions", "/api/v1/traffic/mirror-interface", "/api/v1/situation/target-location", "/api/v1/system/time",
		"/api/v1/incidents/", "/api/v1/incidents", "/api/v1/timeline/", "/api/v1/timeline",
		"/api/v1/rasp/stats", "/api/v1/rasp/events", "/api/v1/rasp/rules", "/api/v1/rasp/agents",
		"/api/v1/rasp/protection/enable", "/api/v1/rasp/protection/disable", "/api/v1/rasp/protection/status",
		"/api/v1/rasp/event", "/api/v1/rasp/elkeid-rules", "/api/v1/trace/stats", "/api/v1/trace/sessions",
		"/api/v1/trace/sessions/{id}", "/api/v1/trace/events", "/api/v1/trace/analyze", "/api/v1/trace/search",
		"/api/v1/assets/stats", "/api/v1/assets", "/api/v1/assets/", "/api/v1/assets/groups", "/api/v1/assets/heartbeat",
		"/api/v1/agents/", "/api/v1/agents", "/api/v1/agent/capabilities/", "/api/v1/agent/name/", "/api/v1/agent/names",
		"/api/v1/agent/enroll", "/api/v1/agent/heartbeat", "/api/v1/agent/config", "/api/v1/agent/identity", "/api/v1/agent/traffic-event",
		"/api/v1/agent/task-result", "/api/v1/agent/component-alert", "/api/v1/agent/runtime-event", "/api/v1/agent/realtime", "/api/v1/agent/install-config",
		"/api/v1/agent/install.sh", "/api/v1/agent/uninstall.sh", "/api/v1/agent/download", "/api/v1/agent/rasp/probe/python",
		"/api/v1/agent/rasp/probe/php", "/api/v1/agent/rasp/probe/java", "/api/v1/agent/rasp/probe/java/source/",
		"/api/v1/agent/rasp/probe/nodejs", "/api/v1/agent/rasp/probe/dotnet", "/api/v1/agent/snapshot", "/api/v1/realtime",
	}
	specs := make([]RouteSpec, 0, len(paths))
	for _, path := range paths {
		spec := RouteSpec{Path: path, Group: routeGroup(path), ReadRoles: allRoles, WriteRoles: operatorRoles}
		switch {
		case public[path]:
			spec.Public, spec.ReadRoles, spec.WriteRoles = true, nil, nil
		case agentCredential[path]:
			spec.AgentCredential, spec.ReadRoles, spec.WriteRoles = true, nil, nil
		case path == "/api/v1/auth/bootstrap-token":
			spec.LoopbackOnly, spec.ReadRoles, spec.WriteRoles = true, nil, nil
		case adminOnly[path]:
			spec.ReadRoles, spec.WriteRoles = adminRoles, adminRoles
		}
		specs = append(specs, spec)
	}
	return specs
}

func routeGroup(path string) string {
	trimmed := strings.TrimPrefix(path, "/api/v1/")
	if path == "/" {
		return "public"
	}
	group, _, _ := strings.Cut(trimmed, "/")
	switch group {
	case "health":
		return "public"
	case "incidents", "timeline":
		return "event"
	case "assets":
		return "asset"
	case "agents":
		return "agent"
	case "rasp":
		return "rasp"
	case "realtime":
		return "realtime"
	case "auth":
		return "auth"
	case "xdr", "rules", "rule-platform":
		return "xdr"
	case "agent":
		return "runtime"
	default:
		return "event"
	}
}
