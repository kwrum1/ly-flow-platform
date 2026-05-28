package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHubBroadcastsIncidentNotification(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?user_id=tester"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()

	want := map[string]interface{}{"type": "incident.updated", "freshness": "fresh", "payload": map[string]interface{}{"chain_id": "chain-1"}}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}
	hub.Broadcast(data)

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read websocket message: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(message, &got); err != nil {
		t.Fatalf("message is not JSON: %v", err)
	}
	if got["type"] != "incident.updated" || got["freshness"] != "fresh" {
		t.Fatalf("unexpected notification: %#v", got)
	}
}

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

func (f httpHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}
