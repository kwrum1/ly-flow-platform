package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestProductionResponseSurface_has_no_host_action_dispatch_route_registry_or_adapter(t *testing.T) {
	// Given
	root := filepath.Clean("../..")
	forbiddenActions := []string{"firewall_block", "process_kill", "file_delete", "account_disable", "namespace_isolate"}
	forbiddenIdentifiers := map[string]string{
		"firewall_block": "ActionFirewallBlock", "process_kill": "ActionProcessKill",
		"file_delete": "ActionFileDelete", "account_disable": "ActionAccountDisable",
		"namespace_isolate": "ActionNamespaceIsolate",
	}
	forbiddenRouteParts := []string{"/execute", "/dispatch", "/firewall", "/process", "/file", "/account", "/namespace"}
	var violations []string

	// When
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// This gate protects the advisory-only surface. Executable response
		// actions live in server/response and /api/v1/response/actions and are
		// covered by their own approval, safety, and execution tests.
		relativeAdvisory := strings.Contains(path, string(os.PathSeparator)+"advisoryresponse"+string(os.PathSeparator)) ||
			strings.HasSuffix(path, string(os.PathSeparator)+"advisory_response.go")
		if !relativeAdvisory {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range parsed.Imports {
			value, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return err
			}
			if strings.Contains(value, "/agent/firewall") {
				violations = append(violations, path+": imports firewall adapter")
			}
			if strings.Contains(path, "advisoryresponse") || strings.Contains(path, "advisory_response") {
				switch value {
				case "os", "os/exec", "syscall":
					violations = append(violations, path+": advisory production imports "+value)
				}
			}
		}
		text := string(source)
		if strings.Contains(text, "func (") && strings.Contains(text, " Simulate(") {
			violations = append(violations, path+": production simulation adapter")
		}
		for _, action := range forbiddenActions {
			if strings.Contains(text, `Action("`+action+`")`) || strings.Contains(text, forbiddenIdentifiers[action]) {
				violations = append(violations, path+": registers "+action)
			}
		}
		full, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return err
		}
		ast.Inspect(full, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil || !strings.Contains(value, "/api/v1/response/") {
				return true
			}
			for _, part := range forbiddenRouteParts {
				if strings.Contains(value, part) {
					violations = append(violations, path+": mounts "+value)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan production Go sources: %v", err)
	}

	// Then
	if _, err := os.Stat(filepath.Join(root, "agent", "firewall", "firewall.go")); !os.IsNotExist(err) {
		violations = append(violations, "agent/firewall production adapter package remains registered")
	}
	if len(violations) != 0 {
		t.Fatalf("production response dispatch violations: %v", violations)
	}
}
