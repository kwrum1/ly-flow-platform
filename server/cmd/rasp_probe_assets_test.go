package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentRASPJavaSourceHandlerServesAllBuildAssets(t *testing.T) {
	oldWd, _ := os.Getwd()
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	handler := agentRASPJavaSourceHandler()
	for _, asset := range []string{"LyRaspAgent.java", "LyRaspSecurityManager.java", "LyRaspJdbcDriver.java", "MANIFEST.MF", "build.sh"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/rasp/probe/java/source/"+asset, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", asset, rec.Code, rec.Body.String())
		}
		if strings.TrimSpace(rec.Body.String()) == "" {
			t.Fatalf("%s served empty body", asset)
		}
	}
}

func TestAgentRASPJavaProbePrefersJarEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/rasp/probe/java", nil)
	rec := httptest.NewRecorder()
	agentRASPProbeHandler("java").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected status %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); rec.Code == http.StatusOK && !strings.Contains(got, "application/java-archive") {
		t.Fatalf("java probe content-type=%q", got)
	}
}
