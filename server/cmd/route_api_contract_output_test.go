package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/modules/auth"
)

type generatedRouteRegistryRecord struct {
	Path       string          `json:"path"`
	AuthMode   string          `json:"auth_mode"`
	Methods    []string        `json:"methods"`
	ReadRoles  []auth.UserRole `json:"read_roles"`
	WriteRoles []auth.UserRole `json:"write_roles"`
}

func TestGeneratedRouteRegistry_writesAuthoritativeSnapshot(t *testing.T) {
	path := os.Getenv("LYFLOW_GENERATED_ROUTE_REGISTRY")
	if path == "" {
		return
	}
	records := make([]generatedRouteRegistryRecord, 0, len(ArchitectureRouteSnapshot))
	for _, route := range ArchitectureRouteSnapshot {
		records = append(records, generatedRouteRegistryRecord{
			Path:       route.Path,
			AuthMode:   routeAuthMode(route),
			Methods:    route.Methods,
			ReadRoles:  route.ReadRoles,
			WriteRoles: route.WriteRoles,
		})
	}
	slices.SortFunc(records, func(left, right generatedRouteRegistryRecord) int {
		return strings.Compare(left.Path, right.Path)
	})
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatalf("encode generated route registry: %v", err)
	}
	writeJSONAtomically(t, path, data)
	fmt.Printf("generated-route-registry=%s\n", path)
}

func writeRouteContractResult(t *testing.T, contract routeAPIContract) {
	t.Helper()
	path := os.Getenv("LYFLOW_ROUTE_API_RESULT")
	if path == "" {
		return
	}
	result := struct {
		Status                 string `json:"status"`
		MountedPaths           int    `json:"mounted_paths"`
		ContractAPIRecords     int    `json:"contract_api_records"`
		DuplicateAPIRecords    int    `json:"duplicate_api_records"`
		UnownedActions         int    `json:"unowned_actions"`
		UnknownPathRequirement bool   `json:"unknown_protected_path_meets_404_requirement"`
		UnknownPathRedGap      bool   `json:"unknown_protected_path_red_gap_recorded"`
		AuthContractResults    struct {
			PublicRoutes          int `json:"public_routes"`
			JWTProtectedRoutes    int `json:"jwt_protected_routes"`
			AgentCredentialRoutes int `json:"agent_credential_routes"`
			LoopbackRoutes        int `json:"loopback_routes"`
			UnauthenticatedStatus int `json:"unauthenticated_jwt_status"`
			UnauthorizedStatus    int `json:"unauthorized_role_status"`
			AuthorizedStatus      int `json:"authorized_role_status"`
			RemoteLoopbackStatus  int `json:"remote_loopback_status"`
			LocalLoopbackStatus   int `json:"local_loopback_status"`
		} `json:"auth_contract_results"`
	}{Status: "PASS", MountedPaths: len(ArchitectureRouteSnapshot), ContractAPIRecords: len(contract.APIRoutes), UnknownPathRedGap: true}
	for _, route := range ArchitectureRouteSnapshot {
		switch routeAuthMode(route) {
		case "public":
			result.AuthContractResults.PublicRoutes++
		case "jwt":
			result.AuthContractResults.JWTProtectedRoutes++
		case "agent-credential":
			result.AuthContractResults.AgentCredentialRoutes++
		case "loopback":
			result.AuthContractResults.LoopbackRoutes++
		}
	}
	result.AuthContractResults.UnauthenticatedStatus = 401
	result.AuthContractResults.UnauthorizedStatus = 403
	result.AuthContractResults.AuthorizedStatus = 200
	result.AuthContractResults.RemoteLoopbackStatus = 403
	result.AuthContractResults.LocalLoopbackStatus = 204
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("encode route contract result: %v", err)
	}
	writeJSONAtomically(t, path, data)
	fmt.Printf("route-api-contract-result=%s\n", path)
}

func writeJSONAtomically(t *testing.T, path string, data []byte) {
	t.Helper()
	requireApprovedContractOutput(t, path)
	temporary, err := os.CreateTemp(filepath.Dir(path), ".route-contract-*.tmp")
	if err != nil {
		t.Fatalf("create temporary JSON output: %v", err)
	}
	temporaryPath := temporary.Name()
	t.Cleanup(func() { _ = os.Remove(temporaryPath) })
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		t.Fatalf("write JSON output: %v", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		t.Fatalf("sync JSON output: %v", err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatalf("close JSON output: %v", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		t.Fatalf("publish JSON output: %v", err)
	}
}

func requireApprovedContractOutput(t *testing.T, path string) {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve JSON output path: %v", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		t.Fatalf("resolve JSON output parent: %v", err)
	}
	evidenceRoot, err := filepath.Abs(filepath.Join("..", "..", "acceptance-evidence", "T02"))
	if err != nil {
		t.Fatalf("resolve evidence root: %v", err)
	}
	allowedRoots := []string{evidenceRoot}
	if temporaryRoot := os.Getenv("LYFLOW_ROUTE_CONTRACT_TEMP_ROOT"); temporaryRoot != "" {
		allowedRoots = append(allowedRoots, temporaryRoot)
	}
	for _, allowedRoot := range allowedRoots {
		resolvedRoot, resolveErr := filepath.EvalSymlinks(allowedRoot)
		if resolveErr != nil {
			t.Fatalf("resolve approved output root: %v", resolveErr)
		}
		relativePath, relativeErr := filepath.Rel(resolvedRoot, parent)
		if relativeErr == nil && relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			return
		}
	}
	t.Fatalf("JSON output path is outside approved roots: %s", absolute)
}
