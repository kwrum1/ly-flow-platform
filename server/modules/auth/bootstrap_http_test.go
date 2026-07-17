package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBootstrapLoopbackHTTPRealSurfaceHasOneWinnerAndCloses(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store := &memoryBootstrapStore{}
	var output bytes.Buffer
	manager := newTestBootstrapManager(store, &output, now)
	if err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute); err != nil {
		t.Fatalf("issue token: %v", err)
	}
	handler := NewBootstrapHandler(manager)
	server := httptest.NewServer(http.HandlerFunc(handler.Consume))
	t.Cleanup(server.Close)
	body := `{"token":"` + strings.TrimSpace(output.String()) + `","username":"admin","password":"LyFlow/2026"}`

	// When
	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			response, err := server.Client().Post(server.URL, "application/json", strings.NewReader(body))
			if err != nil {
				statuses <- 0
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	first, second := <-statuses, <-statuses
	closed, err := server.Client().Post(server.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("closed request: %v", err)
	}
	defer closed.Body.Close()

	// Then
	successes := 0
	for _, status := range []int{first, second} {
		if status == http.StatusCreated {
			successes++
		}
	}
	if successes != 1 || closed.StatusCode != http.StatusNotFound {
		t.Fatalf("statuses=(%d,%d) closed=%d", first, second, closed.StatusCode)
	}
}

func TestBootstrapConsumeRejectsTrailingJSONAfterOneObject(t *testing.T) {
	// Given
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	store := &memoryBootstrapStore{}
	var output bytes.Buffer
	manager := newTestBootstrapManager(store, &output, now)
	if err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute); err != nil {
		t.Fatalf("issue token: %v", err)
	}
	handler := NewBootstrapHandler(manager)
	body := `{"token":"` + strings.TrimSpace(output.String()) + `","username":"admin","password":"LyFlow/2026"}{"extra":true}`
	req := httptest.NewRequest(http.MethodPost, "/bootstrap/consume", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	// When
	handler.Consume(rec, req)

	// Then
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if payload["error_code"] != "invalid_request" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

type failingBootstrapWriter struct{}

func (failingBootstrapWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestBootstrapTokenDisplayInterruptionRevokesStoredToken(t *testing.T) {
	// Given
	store := &memoryBootstrapStore{}
	manager := NewBootstrapTokenManager(store, NewService("test-secret", time.Hour), failingBootstrapWriter{})
	manager.random = bytes.NewReader(bytes.Repeat([]byte{0x3c}, 32))
	manager.now = func() time.Time { return time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC) }

	// When
	err := manager.Issue(context.Background(), BootstrapCreate, 15*time.Minute)

	// Then
	if err == nil || !store.used {
		t.Fatalf("error=%v revoked=%v", err, store.used)
	}
}
