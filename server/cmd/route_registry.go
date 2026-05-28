package main

type RouteSpec struct {
	Method string
	Path   string
	Group  string
}

var ArchitectureRouteSnapshot = []RouteSpec{
	{Method: "GET", Path: "/api/v1/health", Group: "public"},
	{Method: "GET", Path: "/api/v1/public/situation/global", Group: "public"},
	{Method: "POST", Path: "/api/v1/auth/login", Group: "auth"},
	{Method: "POST", Path: "/api/v1/auth/logout", Group: "auth"},
	{Method: "GET", Path: "/api/v1/assets", Group: "asset"},
	{Method: "GET", Path: "/api/v1/assets/:id", Group: "asset"},
	{Method: "GET", Path: "/api/v1/agents", Group: "agent"},
	{Method: "GET", Path: "/api/v1/agents/:id", Group: "agent"},
	{Method: "GET", Path: "/api/v1/events", Group: "event"},
	{Method: "GET", Path: "/api/v1/incidents", Group: "event"},
	{Method: "GET", Path: "/api/v1/incidents/:id", Group: "event"},
	{Method: "GET", Path: "/api/v1/timeline", Group: "event"},
	{Method: "GET", Path: "/api/v1/timeline/:id", Group: "event"},
	{Method: "GET", Path: "/api/v1/xdr/events", Group: "xdr"},
	{Method: "GET", Path: "/api/v1/rules", Group: "xdr"},
	{Method: "GET", Path: "/api/v1/rasp/events", Group: "rasp"},
	{Method: "POST", Path: "/api/v1/agent/runtime-event", Group: "runtime"},
	{Method: "GET", Path: "/api/v1/realtime", Group: "realtime"},
}

func RouteGroups() map[string]int {
	groups := map[string]int{}
	for _, route := range ArchitectureRouteSnapshot {
		groups[route.Group]++
	}
	return groups
}
