package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// mountedMuxPaths 解析 main.go 中所有 mux.Handle / mux.HandleFunc 的字面量路径。
func mountedMuxPaths(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	mounted := make(map[string]bool, len(ArchitectureRouteSnapshot))
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
		mounted[path] = true
		return true
	})
	return mounted
}

// TestRouteRegistryEveryPolicyIsMounted 防止"处理器已实现但未挂路由"这类静默 404。
// 与 TestRouteRegistryCoversEveryMountedPath 互为反向：那条保证已挂载的都有策略，
// 这条保证有策略的都真的挂载了。
func TestRouteRegistryEveryPolicyIsMounted(t *testing.T) {
	mounted := mountedMuxPaths(t)
	// 带 {id} 的策略由前缀路由承接（如 /api/v2/events/{id} 由 /api/v2/events/ 挂载）。
	prefixMounted := func(path string) bool {
		prefix, _, found := strings.Cut(path, "{id}")
		if !found {
			return false
		}
		return mounted[prefix] || mounted[strings.TrimSuffix(prefix, "/")]
	}

	var missing []string
	for _, spec := range ArchitectureRouteSnapshot {
		if !mounted[spec.Path] && !prefixMounted(spec.Path) {
			missing = append(missing, spec.Path)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("route policies without a mounted handler (silent 404): %v", missing)
	}
}

// TestAdvisoryResponseRoutesMounted 是 P0-2 的回归锚点：
// 审批响应处理器与测试都已存在，但曾因未在 main.go 注册而整条链路返回 404。
func TestAdvisoryResponseRoutesMounted(t *testing.T) {
	mounted := mountedMuxPaths(t)
	for _, path := range []string{"/api/v1/response/advisories", "/api/v1/response/advisories/"} {
		if !mounted[path] {
			t.Fatalf("advisory response route %s is not mounted in main.go", path)
		}
		spec, found := findRouteSpec(path)
		if !found {
			t.Fatalf("advisory response route %s has no route policy", path)
		}
		if spec.Public || spec.AgentCredential || spec.LoopbackOnly {
			t.Fatalf("advisory response route %s must require an authenticated user, got %#v", path, spec)
		}
	}
}
