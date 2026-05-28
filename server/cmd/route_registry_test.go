package main

import "testing"

func TestArchitectureRouteSnapshotCoversGatewayGroups(t *testing.T) {
	groups := RouteGroups()
	for _, group := range []string{"auth", "agent", "asset", "event", "xdr", "rasp", "runtime", "public", "realtime"} {
		if groups[group] == 0 {
			t.Fatalf("route group %s missing from architecture snapshot: %#v", group, groups)
		}
	}
}

func TestArchitectureRouteSnapshotPreservesCorePaths(t *testing.T) {
	paths := map[string]bool{}
	for _, route := range ArchitectureRouteSnapshot {
		paths[route.Path] = true
	}
	for _, path := range []string{"/api/v1/events", "/api/v1/incidents", "/api/v1/timeline", "/api/v1/assets", "/api/v1/agents"} {
		if !paths[path] {
			t.Fatalf("core route %s missing", path)
		}
	}
}
