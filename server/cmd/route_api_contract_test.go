package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

type routeAPIContract struct {
	SchemaVersion   int                     `json:"schema_version"`
	Registry        routeRegistryContract   `json:"registry"`
	Roles           []auth.UserRole         `json:"roles"`
	FrontendRoutes  []frontendRouteContract `json:"frontend_routes"`
	APIRoutes       []apiRouteContract      `json:"api_routes"`
	ExpectedRedGaps []redGapContract        `json:"expected_red_gaps"`
}

type routeRegistryContract struct {
	MountedPathCount int    `json:"mounted_path_count"`
	SortedPathSHA256 string `json:"sorted_path_sha256"`
}

type frontendRouteContract struct {
	Path           string          `json:"path"`
	Disposition    string          `json:"disposition"`
	CanonicalPaths []string        `json:"canonical_paths"`
	AuthMode       string          `json:"auth_mode"`
	AllowedRoles   []auth.UserRole `json:"allowed_roles"`
	CurrentSources []string        `json:"current_sources"`
	CurrentGap     string          `json:"current_gap,omitempty"`
}

type apiRouteContract struct {
	Path        string                 `json:"path"`
	AuthMode    string                 `json:"auth_mode"`
	Operations  []apiOperationContract `json:"operations"`
	Disposition string                 `json:"disposition"`
	Notes       string                 `json:"notes,omitempty"`
}

type apiOperationContract struct {
	Method         string          `json:"method"`
	AllowedRoles   []auth.UserRole `json:"allowed_roles"`
	ValidFixture   fixtureContract `json:"valid_fixture"`
	InvalidFixture fixtureContract `json:"invalid_fixture"`
	Mutation       bool            `json:"mutation"`
	Readback       string          `json:"readback"`
	Persistence    string          `json:"persistence"`
}

type fixtureContract struct {
	Method           string          `json:"method"`
	Path             string          `json:"path"`
	Body             json.RawMessage `json:"body"`
	ExpectedStatuses []int           `json:"expected_statuses"`
}

type redGapContract struct {
	ID        string `json:"id"`
	Current   string `json:"current"`
	Required  string `json:"required"`
	OwnerTask string `json:"owner_task"`
}

func TestRouteAPIContract_matchesMountedRegistry(t *testing.T) {
	// Given
	contract := loadRouteAPIContract(t)

	// When / Then
	if contract.SchemaVersion != 1 {
		t.Fatalf("schema version=%d, want 1", contract.SchemaVersion)
	}
	if !rolesEqual(contract.Roles, allRoles) {
		t.Fatalf("roles=%v, want %v", contract.Roles, allRoles)
	}
	validateFrontendRouteContract(t, contract.FrontendRoutes, contract.ExpectedRedGaps)
	validateAPIContract(t, contract)
	writeRouteContractResult(t, contract)
}

func loadRouteAPIContract(t *testing.T) routeAPIContract {
	t.Helper()
	path := os.Getenv("LYFLOW_ROUTE_API_CONTRACT")
	if path == "" {
		path = filepath.Join("..", "..", "contracts", "product-acceptance", "v1", "route-api-contract.json")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open route API contract: %v", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var contract routeAPIContract
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode route API contract: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("route API contract has trailing data: %v", err)
	}
	return contract
}

func validateFrontendRouteContract(t *testing.T, routes []frontendRouteContract, gaps []redGapContract) {
	t.Helper()
	byPath := make(map[string]frontendRouteContract, len(routes))
	for _, route := range routes {
		if _, duplicate := byPath[route.Path]; duplicate {
			t.Fatalf("duplicate frontend route: %s", route.Path)
		}
		byPath[route.Path] = route
	}
	canonical := []string{"/dashboard", "/events", "/incidents", "/timeline", "/xdr", "/assets", "/runtime", "/rasp", "/trace", "/rules", "/users", "/install-config", "/traffic-observe", "/traffic-threats", "/control-center"}
	for _, path := range canonical {
		route, found := byPath[path]
		if !found || route.Disposition != "retain" || !slices.Equal(route.CanonicalPaths, []string{path}) {
			t.Fatalf("canonical frontend route %s has contract %#v", path, route)
		}
	}
	consolidations := map[string]string{"/application-threats": "/rasp", "/system-security-audit": "/runtime", "/host-ops": "/assets", "/real-time-posture": "/xdr", "/rule-visibility": "/rules", "/rule-updates": "/rules"}
	for path, target := range consolidations {
		route, found := byPath[path]
		if !found || route.Disposition != "consolidate" || !slices.Equal(route.CanonicalPaths, []string{target}) || route.CurrentGap == "" {
			t.Fatalf("consolidation route %s has contract %#v", path, route)
		}
	}
	fallback, found := byPath["/:pathMatch(.*)*"]
	if !found || fallback.Disposition != "404" || !strings.Contains(fallback.CurrentGap, "/dashboard") {
		t.Fatalf("fallback contract=%#v", fallback)
	}
	gapFound := false
	for _, gap := range gaps {
		if gap.ID == "authenticated-unknown-path-dashboard-fallback" && gap.OwnerTask == "T15" {
			gapFound = true
		}
	}
	if !gapFound {
		t.Fatal("authenticated unknown-path red gap is not explicitly owned by T15")
	}
}

func validateAPIContract(t *testing.T, contract routeAPIContract) {
	t.Helper()
	if contract.Registry.MountedPathCount != len(ArchitectureRouteSnapshot) || len(contract.APIRoutes) != len(ArchitectureRouteSnapshot) {
		t.Fatalf("route counts registry=%d contract-metadata=%d api=%d", len(ArchitectureRouteSnapshot), contract.Registry.MountedPathCount, len(contract.APIRoutes))
	}
	paths := make([]string, 0, len(ArchitectureRouteSnapshot))
	byPath := make(map[string]apiRouteContract, len(contract.APIRoutes))
	for _, route := range contract.APIRoutes {
		if _, duplicate := byPath[route.Path]; duplicate {
			t.Fatalf("duplicate API route record: %s", route.Path)
		}
		byPath[route.Path] = route
	}
	for _, spec := range ArchitectureRouteSnapshot {
		paths = append(paths, spec.Path)
		route, found := byPath[spec.Path]
		if !found {
			t.Fatalf("mounted route missing API contract: %s", spec.Path)
		}
		validateAPIRoute(t, spec, route)
	}
	slices.Sort(paths)
	digest := sha256.Sum256([]byte(strings.Join(paths, "\n") + "\n"))
	if contract.Registry.SortedPathSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("stale registry path digest=%s, want %s", contract.Registry.SortedPathSHA256, hex.EncodeToString(digest[:]))
	}
}

func validateAPIRoute(t *testing.T, spec RouteSpec, route apiRouteContract) {
	t.Helper()
	if route.AuthMode != routeAuthMode(spec) || route.Disposition == "" || len(route.Operations) == 0 {
		t.Fatalf("incomplete API route contract for %s: %#v", spec.Path, route)
	}
	if len(route.Operations) != len(spec.Methods) {
		t.Fatalf("%s operation count=%d, want registry methods %v", route.Path, len(route.Operations), spec.Methods)
	}
	methods := map[string]bool{}
	for _, operation := range route.Operations {
		if methods[operation.Method] {
			t.Fatalf("duplicate API operation %s %s", operation.Method, route.Path)
		}
		methods[operation.Method] = true
		if !slices.Contains(spec.Methods, operation.Method) {
			t.Fatalf("API operation %s %s is absent from the route registry", operation.Method, route.Path)
		}
		expectedRoles := spec.WriteRoles
		if operation.Method == "GET" || operation.Method == "HEAD" || operation.Method == "WS" {
			expectedRoles = spec.ReadRoles
		}
		if !rolesEqual(operation.AllowedRoles, expectedRoles) {
			t.Fatalf("%s %s roles=%v, want %v", operation.Method, route.Path, operation.AllowedRoles, expectedRoles)
		}
		if operation.ValidFixture.Method != operation.Method || operation.ValidFixture.Path == "" || operation.InvalidFixture.Method == "" || operation.InvalidFixture.Path == "" || len(operation.ValidFixture.ExpectedStatuses) == 0 || len(operation.InvalidFixture.ExpectedStatuses) == 0 {
			t.Fatalf("%s %s has incomplete fixtures", operation.Method, route.Path)
		}
		if operation.Readback == "" || operation.Persistence == "" {
			t.Fatalf("%s %s has no mutation expectation", operation.Method, route.Path)
		}
	}
}

func routeAuthMode(spec RouteSpec) string {
	switch {
	case spec.Public:
		return "public"
	case spec.AgentCredential:
		return "agent-credential"
	case spec.LoopbackOnly:
		return "loopback"
	default:
		return "jwt"
	}
}
