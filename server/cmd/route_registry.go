package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

type RouteSpec struct {
	Path            string
	Group           string
	Methods         []string
	Public          bool
	AgentCredential bool
	LoopbackOnly    bool
	ReadRoles       []auth.UserRole
	WriteRoles      []auth.UserRole
}

var (
	allRoles      = []auth.UserRole{auth.RoleAdmin, auth.RoleAnalyst, auth.RoleViewer}
	operatorRoles = []auth.UserRole{auth.RoleAdmin, auth.RoleAnalyst}
	adminRoles    = []auth.UserRole{auth.RoleAdmin}
)

func EnforceRoutePolicy(next http.Handler, middleware *auth.Middleware) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		spec, found := findRouteSpec(request.URL.Path)
		if !found {
			writeRoutePolicyError(w, http.StatusForbidden, "route_not_authorized")
			return
		}
		if spec.Public {
			next.ServeHTTP(w, request)
			return
		}
		if spec.AgentCredential {
			next.ServeHTTP(w, request)
			return
		}
		if spec.LoopbackOnly {
			if !isLoopbackRequest(request.RemoteAddr) {
				writeRoutePolicyError(w, http.StatusForbidden, "loopback_required")
				return
			}
			next.ServeHTTP(w, request)
			return
		}
		roles := spec.WriteRoles
		if request.Method == http.MethodGet || request.Method == http.MethodHead {
			roles = spec.ReadRoles
		}
		if middleware == nil || len(roles) == 0 {
			writeRoutePolicyError(w, http.StatusForbidden, "route_not_authorized")
			return
		}
		middleware.Authenticate(middleware.RequireRole(roles...)(next)).ServeHTTP(w, request)
	})
}

func findRouteSpec(path string) (RouteSpec, bool) {
	for _, spec := range ArchitectureRouteSnapshot {
		if routePathMatches(spec.Path, path) {
			return spec, true
		}
	}
	return RouteSpec{}, false
}

func routePathMatches(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if pattern == "/" {
		return path == "/"
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}
	if strings.Contains(pattern, "{id}") {
		prefix, suffix, _ := strings.Cut(pattern, "{id}")
		value := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
		return strings.HasPrefix(path, prefix) && strings.HasSuffix(path, suffix) && value != "" && !strings.Contains(value, "/")
	}
	return false
}

func isLoopbackRequest(remoteAddr string) bool {
	host := remoteAddr
	if parsed, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsed
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeRoutePolicyError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code      int    `json:"code"`
		ErrorCode string `json:"error_code"`
	}{Code: status, ErrorCode: code})
}

func RouteGroups() map[string]int {
	groups := map[string]int{}
	for _, route := range ArchitectureRouteSnapshot {
		groups[route.Group]++
	}
	return groups
}
