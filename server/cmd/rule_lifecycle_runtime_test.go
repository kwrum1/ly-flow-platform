package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuleRuntimeHTTP_reload_authenticates_as_authorized_control_principal(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer control-secret" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		if request.Header.Get("X-Lyflow-Control-Principal") != "service:ly-server" || request.Header.Get("X-Lyflow-Control-Role") != "admin" {
			t.Errorf("control principal headers = %q/%q", request.Header.Get("X-Lyflow-Control-Principal"), request.Header.Get("X-Lyflow-Control-Role"))
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	runtime := &ruleRuntimeHTTP{client: server.Client(), reloadURL: server.URL, token: "control-secret"}

	// When
	err := runtime.Reload(context.Background(), "/app/rules/active-manifest.json", "digest")

	// Then
	if err != nil {
		t.Fatalf("authenticated runtime reload: %v", err)
	}
}
