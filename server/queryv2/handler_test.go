package queryv2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/analytics"
)

type fakeStore struct {
	query   analytics.EventV2Query
	page    analytics.EventV2Page
	view    analytics.EventV2View
	getErr  error
	listErr error
}

func (store *fakeStore) QueryEventsV2(_ context.Context, query analytics.EventV2Query) (analytics.EventV2Page, error) {
	store.query = query
	return store.page, store.listErr
}

func (store *fakeStore) GetEventV2(_ context.Context, _ string) (analytics.EventV2View, error) {
	return store.view, store.getErr
}

func TestListAppliesFilters(t *testing.T) {
	store := &fakeStore{page: analytics.EventV2Page{Items: []analytics.EventV2View{{EventUID: "evt-1"}}}}
	handler := Handler{Store: store}
	request := httptest.NewRequest(http.MethodGet,
		"/api/v2/events?from=2026-10-18T00:00:00Z&to=2026-10-19T00:00:00Z&source=adapter.suricata&severity=high&limit=10&q=8.8.8.8", nil)
	recorder := httptest.NewRecorder()
	handler.List(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if store.query.Source != "adapter.suricata" || store.query.Severity != "high" || store.query.Limit != 10 {
		t.Fatalf("filters not applied: %+v", store.query)
	}
	if store.query.Query != "8.8.8.8" {
		t.Fatalf("keyword not applied: %+v", store.query)
	}
	if !store.query.From.Equal(time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("from = %s", store.query.From)
	}
}

func TestListRejectsInvalidLimit(t *testing.T) {
	handler := Handler{Store: &fakeStore{}}
	request := httptest.NewRequest(http.MethodGet, "/api/v2/events?limit=0", nil)
	recorder := httptest.NewRecorder()
	handler.List(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
}

func TestListRejectsRangeOver30Days(t *testing.T) {
	handler := Handler{Store: &fakeStore{}}
	request := httptest.NewRequest(http.MethodGet,
		"/api/v2/events?from=2026-09-01T00:00:00Z&to=2026-10-19T00:00:00Z", nil)
	recorder := httptest.NewRecorder()
	handler.List(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
}

func TestListRejectsInvalidCursor(t *testing.T) {
	handler := Handler{Store: &fakeStore{}}
	request := httptest.NewRequest(http.MethodGet, "/api/v2/events?cursor=not-base64", nil)
	recorder := httptest.NewRecorder()
	handler.List(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
}

func TestListReportsStoreFailure(t *testing.T) {
	handler := Handler{Store: &fakeStore{listErr: errors.New("down")}}
	request := httptest.NewRequest(http.MethodGet, "/api/v2/events", nil)
	recorder := httptest.NewRecorder()
	handler.List(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", recorder.Code)
	}
}

func TestGetReturnsEvent(t *testing.T) {
	handler := Handler{Store: &fakeStore{view: analytics.EventV2View{EventUID: "evt-1"}}}
	request := httptest.NewRequest(http.MethodGet, "/api/v2/events/evt-1", nil)
	recorder := httptest.NewRecorder()
	handler.Get(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestGetReturnsNotFound(t *testing.T) {
	handler := Handler{Store: &fakeStore{getErr: analytics.ErrEventV2NotFound}}
	request := httptest.NewRequest(http.MethodGet, "/api/v2/events/missing", nil)
	recorder := httptest.NewRecorder()
	handler.Get(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", recorder.Code)
	}
}

func TestHandlersRejectWrongMethod(t *testing.T) {
	handler := Handler{Store: &fakeStore{}}
	for _, call := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"list", handler.List},
		{"get", handler.Get},
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v2/events", nil)
		recorder := httptest.NewRecorder()
		call.fn(recorder, request)
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status=%d, want 405", call.name, recorder.Code)
		}
	}
}
