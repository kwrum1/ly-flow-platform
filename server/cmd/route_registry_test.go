package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

func TestArchitectureRouteSnapshotCoversGatewayGroups(t *testing.T) {
	groups := RouteGroups()
	for _, group := range []string{"auth", "agent", "asset", "event", "xdr", "rasp", "runtime", "public", "realtime"} {
		if groups[group] == 0 {
			t.Fatalf("route group %s missing from architecture snapshot: %#v", group, groups)
		}
	}
}

func TestArchitectureRouteSnapshot_characterizesCurrentCountAndRoles(t *testing.T) {
	// Given
	counts := map[string]int{
		"public":           0,
		"agent_credential": 0,
		"loopback":         0,
		"admin_only":       0,
		"default_roles":    0,
	}

	// When
	for _, route := range ArchitectureRouteSnapshot {
		switch {
		case route.Public:
			counts["public"]++
		case route.AgentCredential:
			counts["agent_credential"]++
		case route.LoopbackOnly:
			counts["loopback"]++
		case rolesEqual(route.ReadRoles, adminRoles) && rolesEqual(route.WriteRoles, adminRoles):
			counts["admin_only"]++
		case rolesEqual(route.ReadRoles, allRoles) && rolesEqual(route.WriteRoles, operatorRoles):
			counts["default_roles"]++
		default:
			t.Fatalf("uncharacterized route policy for %s: %#v", route.Path, route)
		}
	}

	// Then
	if len(ArchitectureRouteSnapshot) != 120 {
		t.Fatalf("route snapshot count=%d, want 120", len(ArchitectureRouteSnapshot))
	}
	want := map[string]int{
		"public":           11,
		"agent_credential": 11,
		"loopback":         1,
		"admin_only":       24,
		"default_roles":    73,
	}
	for class, expected := range want {
		if counts[class] != expected {
			t.Fatalf("%s route count=%d, want %d", class, counts[class], expected)
		}
	}
}

func TestRouteRegistryCoversEveryMountedPath(t *testing.T) {
	// Given
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	registered := make(map[string]bool, len(ArchitectureRouteSnapshot))
	for _, route := range ArchitectureRouteSnapshot {
		if registered[route.Path] {
			t.Fatalf("duplicate route policy for %s", route.Path)
		}
		registered[route.Path] = true
	}

	// When
	var missing []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc" {
			return true
		}
		identifier, identifierOK := selector.X.(*ast.Ident)
		literal, literalOK := call.Args[0].(*ast.BasicLit)
		if !identifierOK || identifier.Name != "mux" || !literalOK || literal.Kind != token.STRING {
			return true
		}
		path, unquoteErr := strconv.Unquote(literal.Value)
		if unquoteErr != nil {
			t.Fatalf("unquote route path: %v", unquoteErr)
		}
		if !registered[path] {
			missing = append(missing, path)
		}
		return true
	})

	// Then
	if len(missing) != 0 {
		t.Fatalf("mounted paths missing policy: %v", missing)
	}
}

func TestRouteRegistryDenyByDefaultAndEnforcesRoles(t *testing.T) {
	// Given
	unknown := httptest.NewRequest(http.MethodGet, "/api/v1/not-registered", nil)
	response := httptest.NewRecorder()
	handler := EnforceRoutePolicy(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unknown route reached handler")
	}), nil)

	// When
	handler.ServeHTTP(response, unknown)
	register, registerFound := findRouteSpec("/api/v1/auth/register")
	events, eventsFound := findRouteSpec("/api/v1/events")
	health, healthFound := findRouteSpec("/api/v1/health")
	global, globalFound := findRouteSpec("/api/v1/public/situation/global")

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("unknown route status=%d", response.Code)
	}
	if !registerFound || !rolesEqual(register.WriteRoles, adminRoles) {
		t.Fatalf("register policy=%#v", register)
	}
	if !eventsFound || rolePresent(events.WriteRoles, auth.RoleViewer) || !rolePresent(events.WriteRoles, auth.RoleAnalyst) {
		t.Fatalf("events policy=%#v", events)
	}
	if !healthFound || !health.Public || !globalFound || global.Public {
		t.Fatalf("public policies health=%#v global=%#v", health, global)
	}
}

func TestArchitectureRouteSnapshotMarksPublicAndProtectedRoutes(t *testing.T) {
	publicRoutePaths := map[string]bool{
		"/api/v1/health": true, "/api/v1/auth/login": true,
		"/api/v1/agent/install.sh": true, "/api/v1/agent/uninstall.sh": true,
		"/api/v1/agent/download": true, "/api/v1/agent/rasp/probe/python": true,
		"/api/v1/agent/rasp/probe/php": true, "/api/v1/agent/rasp/probe/java": true,
		"/api/v1/agent/rasp/probe/java/source/": true,
		"/api/v1/agent/rasp/probe/nodejs":       true, "/api/v1/agent/rasp/probe/dotnet": true,
	}
	publicCount := 0
	agentCredentialPaths := map[string]bool{
		"/api/v1/agent/enroll":          true,
		"/api/v1/agent/heartbeat":       true,
		"/api/v1/agent/config":          true,
		"/api/v1/agent/traffic-event":   true,
		"/api/v1/agent/task-result":     true,
		"/api/v1/agent/component-alert": true,
		"/api/v1/agent/runtime-event":   true,
		"/api/v1/agent/realtime":        true,
		"/api/v1/agent/snapshot":        true,
		"/api/v1/rasp/event":            true,
		"/api/v2/ingest/events":         true,
	}
	for _, route := range ArchitectureRouteSnapshot {
		if len(route.Methods) == 0 {
			t.Fatalf("route has no methods: %s", route.Path)
		}
		methodSeen := map[string]bool{}
		for _, method := range route.Methods {
			if methodSeen[method] {
				t.Fatalf("route has duplicate method %s: %s", method, route.Path)
			}
			methodSeen[method] = true
		}
		if route.Public {
			publicCount++
			if !publicRoutePaths[route.Path] {
				t.Fatalf("unexpected public route: %s", route.Path)
			}
			continue
		}
		if route.LoopbackOnly {
			if route.Path != "/api/v1/auth/bootstrap-token" {
				t.Fatalf("unexpected loopback route: %s", route.Path)
			}
			continue
		}
		if route.AgentCredential {
			if !agentCredentialPaths[route.Path] {
				t.Fatalf("unexpected Agent credential route: %s", route.Path)
			}
			continue
		}
		if len(route.ReadRoles) == 0 && len(route.WriteRoles) == 0 {
			t.Fatalf("protected route has no roles: %s", route.Path)
		}
	}
	if publicCount != 11 {
		t.Fatalf("public route count=%d, want 11", publicCount)
	}
}

func TestRuleLifecycleMutationRoutes_require_admin(t *testing.T) {
	// Given
	paths := []string{
		"/api/v1/rules", "/api/v1/rules/items/example", "/api/v1/rules/sources", "/api/v1/rules/sources/example",
		"/api/v1/rules/update", "/api/v1/rules/test", "/api/v1/rule-platform/sources", "/api/v1/rule-platform/sync",
		"/api/v1/rule-platform/compile-preview", "/api/v1/rule-platform/active-bundle", "/api/v1/rule-platform/rollback",
		"/api/v1/engine-rules", "/api/v1/engine-rules/update", "/api/v1/rasp/rules",
	}

	// When / Then
	for _, path := range paths {
		spec, found := findRouteSpec(path)
		if !found || !rolesEqual(spec.WriteRoles, adminRoles) {
			t.Fatalf("rule mutation route %s is not admin-only: %#v", path, spec)
		}
	}
}

func rolePresent(roles []auth.UserRole, expected auth.UserRole) bool {
	for _, role := range roles {
		if role == expected {
			return true
		}
	}
	return false
}

func rolesEqual(left, right []auth.UserRole) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
