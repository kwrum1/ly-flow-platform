package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestInferAPIServerRejectsHostInjection(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.com/api", nil)
	request.Host = `evil.example"; touch /tmp/lyflow-pwn; echo "`
	if _, ok := inferAPIServer(request); ok {
		t.Fatal("accepted shell metacharacters in Host")
	}
	request.Host = "bad_host.example.com"
	if _, ok := inferAPIServer(request); ok {
		t.Fatal("accepted invalid hostname")
	}
}

func TestInferAPIServerIgnoresForwardedHost(t *testing.T) {
	request := httptest.NewRequest("GET", "http://example.com/api", nil)
	request.Header.Set("X-Forwarded-Host", `evil.example"; touch /tmp/lyflow-pwn; echo "`)
	request.Header.Set("X-Forwarded-Port", `not-a-port`)
	got, ok := inferAPIServer(request)
	if !ok || got != "http://example.com:8080" {
		t.Fatalf("inferAPIServer = %q, %v", got, ok)
	}
}

func TestInferAPIServerValidHosts(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"example.com", "http://example.com:8080"},
		{"example.com:8443", "http://example.com:8443"},
		{"127.0.0.1:8080", "http://127.0.0.1:8080"},
		{"[2001:db8::1]:8080", "http://[2001:db8::1]:8080"},
	}
	for _, test := range tests {
		request := httptest.NewRequest("GET", "http://example.com/api", nil)
		request.Host = test.raw
		got, ok := inferAPIServer(request)
		if !ok || got != test.want {
			t.Fatalf("%s: got %q, %v; want %q", test.raw, got, ok, test.want)
		}
	}
}
