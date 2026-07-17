package websocket

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lyflow/ly-flow-platform/server/agentidentity"
	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
)

const expectedAgentMessageOversizeReason = "message exceeds 512-byte limit"

func TestHubBroadcastsIncidentNotification(t *testing.T) {
	hub := NewAuthenticatedHub(func(*http.Request) (string, error) { return "user-7", nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?user_id=user-7"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer conn.Close()
	waitForConnectedClients(t, hub, 1)

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

func TestWebSocketRejectsUnauthenticatedAndConflictingPrincipal(t *testing.T) {
	// Given
	unauthenticated := NewAuthenticatedHub(func(*http.Request) (string, error) { return "", ErrUnauthenticated })
	unauthenticatedServer := httptest.NewServer(httpHandlerFunc(unauthenticated.HandleWebSocket))
	defer unauthenticatedServer.Close()
	conflicting := NewAuthenticatedHub(func(*http.Request) (string, error) { return "user-7", nil })
	conflictingServer := httptest.NewServer(httpHandlerFunc(conflicting.HandleWebSocket))
	defer conflictingServer.Close()

	// When
	_, unauthenticatedResponse, unauthenticatedErr := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(unauthenticatedServer.URL, "http"), nil)
	_, conflictingResponse, conflictingErr := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(conflictingServer.URL, "http")+"?user_id=user-8", nil)

	// Then
	if unauthenticatedErr == nil || unauthenticatedResponse == nil || unauthenticatedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated response = %#v error = %v", unauthenticatedResponse, unauthenticatedErr)
	}
	if conflictingErr == nil || conflictingResponse == nil || conflictingResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("conflicting response = %#v error = %v", conflictingResponse, conflictingErr)
	}
}

func TestWebSocketLimitsConcurrentConnectionsPerPrincipal(t *testing.T) {
	// Given
	hub := NewAuthenticatedHub(func(*http.Request) (string, error) { return "user-7", nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")
	connections := make([]*websocket.Conn, 0, 4)
	for index := 0; index < 4; index++ {
		connection, _, err := websocket.DefaultDialer.Dial(websocketURL, nil)
		if err != nil {
			t.Fatalf("dial connection %d: %v", index, err)
		}
		connections = append(connections, connection)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()

	// When
	_, response, err := websocket.DefaultDialer.Dial(websocketURL, nil)

	// Then
	if err == nil || response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("fifth connection response = %#v error = %v", response, err)
	}
}

func TestWebSocketRejectsCrossOriginUpgrade(t *testing.T) {
	// Given
	hub := NewAuthenticatedHub(func(*http.Request) (string, error) { return "user-7", nil })
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	headers := http.Header{"Origin": []string{"https://attacker.invalid"}}

	// When
	_, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), headers)

	// Then
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin response = %#v error = %v", response, err)
	}
}

func TestAgentWebSocketRequiresMigratedAgentPrincipal(t *testing.T) {
	// Given
	authenticator, audit := agentWebSocketAuthenticator(t, nil)
	hub := NewAgentHub(authenticator, AgentHubOptions{MessagesPerMinute: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	validHeaders := http.Header{
		ingestionauth.AgentIDHeader: []string{"agent-1"},
		"Authorization":             []string{"Bearer legacy-secret"},
	}
	consoleHeaders := http.Header{"Authorization": []string{"Bearer console-session"}}

	// When
	connection, _, validErr := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), validHeaders)
	_, consoleResponse, consoleErr := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), consoleHeaders)

	// Then
	if validErr != nil {
		t.Fatalf("valid Agent principal dial: %v", validErr)
	}
	defer connection.Close()
	if consoleErr == nil || consoleResponse == nil || consoleResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("console-only response = %#v error = %v", consoleResponse, consoleErr)
	}
	if events := audit.Events(); len(events) < 3 || events[1].Outcome != ingestionauth.OutcomeAccepted {
		t.Fatalf("Agent WebSocket audit events = %#v", events)
	}
}

func TestAgentWebSocketMessageRateLimitAndOriginPolicy(t *testing.T) {
	// Given
	authenticator, audit := agentWebSocketAuthenticator(t, nil)
	hub := NewAgentHub(authenticator, AgentHubOptions{MessagesPerMinute: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	headers := http.Header{
		ingestionauth.AgentIDHeader: []string{"agent-1"},
		"Authorization":             []string{"Bearer legacy-secret"},
	}
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), headers)
	if err != nil {
		t.Fatalf("empty-Origin Agent dial: %v", err)
	}
	defer connection.Close()

	// When
	if err := connection.WriteMessage(websocket.TextMessage, []byte("one")); err != nil {
		t.Fatalf("first message: %v", err)
	}
	if err := connection.WriteMessage(websocket.TextMessage, []byte("two")); err != nil {
		t.Fatalf("second message: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, rateErr := connection.ReadMessage()
	foreignHeaders := headers.Clone()
	foreignHeaders.Set("Origin", "https://attacker.invalid")
	_, foreignResponse, foreignErr := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), foreignHeaders)

	// Then
	if !websocket.IsCloseError(rateErr, websocket.ClosePolicyViolation) {
		t.Fatalf("message rate-limit close error = %v", rateErr)
	}
	if foreignErr == nil || foreignResponse == nil || foreignResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin response = %#v error = %v", foreignResponse, foreignErr)
	}
	events := audit.Events()
	if events[len(events)-1].Outcome != ingestionauth.OutcomeRejected && events[len(events)-1].Outcome != ingestionauth.OutcomeRateLimited {
		t.Fatalf("missing rate/origin audit: %#v", events)
	}
}

func TestAgentWebSocketAuditFailureFailsClosedBeforeUpgrade(t *testing.T) {
	// Given
	authenticator, _ := agentWebSocketAuthenticator(t, &failingWebSocketAudit{outcome: ingestionauth.OutcomeAccepted})
	hub := NewAgentHub(authenticator, AgentHubOptions{MessagesPerMinute: 10})
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	headers := http.Header{
		ingestionauth.AgentIDHeader: []string{"agent-1"},
		"Authorization":             []string{"Bearer legacy-secret"},
	}

	// When
	_, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), headers)

	// Then
	if err == nil || response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("audit failure response = %#v error = %v", response, err)
	}
}

func TestAgentWebSocketOversizedMessageAuditsRejection(t *testing.T) {
	// Given
	executor := &webSocketAuditExecutor{events: make(chan ingestionauth.Event, 8)}
	authenticator, _ := agentWebSocketAuthenticator(t, ingestionauth.NewPostgresAudit(executor))
	hub := NewAgentHub(authenticator, AgentHubOptions{MessagesPerMinute: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	connection := dialAgentWebSocket(t, server.URL)
	defer connection.Close()

	// When
	if err := connection.WriteMessage(websocket.BinaryMessage, make([]byte, 513)); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, closeErr := connection.ReadMessage()
	event := waitForAuditOutcome(t, executor.events, ingestionauth.OutcomeRejected)

	// Then
	if !websocket.IsCloseError(closeErr, websocket.CloseMessageTooBig) {
		t.Fatalf("oversized close error = %v", closeErr)
	}
	if event.Reason != expectedAgentMessageOversizeReason {
		t.Fatalf("oversized audit reason = %q", event.Reason)
	}
}

func TestAgentWebSocketOversizedMessageAuditFailureClosesFailClosed(t *testing.T) {
	// Given
	var logs synchronizedBuffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousLogOutput)
	executor := &webSocketAuditExecutor{events: make(chan ingestionauth.Event, 8), failOutcome: ingestionauth.OutcomeRejected}
	authenticator, _ := agentWebSocketAuthenticator(t, ingestionauth.NewPostgresAudit(executor))
	hub := NewAgentHub(authenticator, AgentHubOptions{MessagesPerMinute: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	connection := dialAgentWebSocket(t, server.URL)
	defer connection.Close()

	// When
	if err := connection.WriteMessage(websocket.BinaryMessage, make([]byte, 513)); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, closeErr := connection.ReadMessage()
	attempt := waitForAuditOutcome(t, executor.events, ingestionauth.OutcomeRejected)
	waitForAuditOutcome(t, executor.events, ingestionauth.OutcomeClosed)

	// Then
	if !websocket.IsCloseError(closeErr, websocket.CloseMessageTooBig) {
		t.Fatalf("audit-failure close error = %v", closeErr)
	}
	if attempt.Reason != expectedAgentMessageOversizeReason {
		t.Fatalf("oversized audit attempt reason = %q", attempt.Reason)
	}
	if strings.Contains(closeErr.Error(), "legacy-secret") {
		t.Fatal("credential leaked in WebSocket close error")
	}
	if !strings.Contains(logs.String(), "WebSocket lifecycle audit persistence failed") {
		t.Fatalf("audit persistence failure was not surfaced: %q", logs.String())
	}
	if strings.Contains(logs.String(), "legacy-secret") {
		t.Fatal("credential leaked in WebSocket lifecycle log")
	}
}

func TestAgentWebSocketNormalCloseIsNotAuditedAsOversizedRejection(t *testing.T) {
	// Given
	executor := &webSocketAuditExecutor{events: make(chan ingestionauth.Event, 8)}
	authenticator, _ := agentWebSocketAuthenticator(t, ingestionauth.NewPostgresAudit(executor))
	hub := NewAgentHub(authenticator, AgentHubOptions{MessagesPerMinute: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)
	server := httptest.NewServer(httpHandlerFunc(hub.HandleWebSocket))
	defer server.Close()
	connection := dialAgentWebSocket(t, server.URL)
	defer connection.Close()

	// When
	closeMessage := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	if err := connection.WriteControl(websocket.CloseMessage, closeMessage, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write normal close: %v", err)
	}

	// Then
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case event := <-executor.events:
			if event.Outcome == ingestionauth.OutcomeRejected {
				t.Fatalf("normal close misclassified as rejection: %#v", event)
			}
			if event.Outcome == ingestionauth.OutcomeClosed {
				return
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for normal close audit")
		}
	}
}

type webSocketAuditExecutor struct {
	events      chan ingestionauth.Event
	failOutcome string
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (e *webSocketAuditExecutor) Exec(_ context.Context, _ string, args ...interface{}) (pgconn.CommandTag, error) {
	if len(args) != 5 {
		return pgconn.NewCommandTag("CREATE TABLE"), nil
	}
	event := ingestionauth.Event{
		AgentID: args[0].(string),
		Surface: args[1].(string),
		Outcome: args[2].(string),
		Reason:  args[3].(string),
		At:      args[4].(time.Time),
	}
	e.events <- event
	if event.Outcome == e.failOutcome {
		return pgconn.CommandTag{}, errors.New("audit persistence failed")
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func dialAgentWebSocket(t *testing.T, serverURL string) *websocket.Conn {
	t.Helper()
	headers := http.Header{
		ingestionauth.AgentIDHeader: []string{"agent-1"},
		"Authorization":             []string{"Bearer legacy-secret"},
	}
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(serverURL, "http"), headers)
	if err != nil {
		t.Fatalf("dial Agent WebSocket: %v", err)
	}
	return connection
}

func waitForAuditOutcome(t *testing.T, events <-chan ingestionauth.Event, outcome string) ingestionauth.Event {
	t.Helper()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case event := <-events:
			if event.Outcome == outcome {
				return event
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for audit outcome %q", outcome)
		}
	}
}

type failingWebSocketAudit struct{ outcome string }

func (a *failingWebSocketAudit) Record(_ context.Context, event ingestionauth.Event) error {
	if event.Outcome == a.outcome {
		return errors.New("audit unavailable")
	}
	return nil
}

func agentWebSocketAuthenticator(t *testing.T, failure ingestionauth.Audit) (*ingestionauth.Authenticator, *ingestionauth.MemoryAudit) {
	t.Helper()
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	manager := agentidentity.NewManager(agentidentity.NewMemoryStore(), func() time.Time { return now })
	id, err := agentidentity.NewAgentID("agent-1")
	if err != nil {
		t.Fatalf("Agent ID: %v", err)
	}
	record, err := agentidentity.NewLegacyRecord(id, "legacy-secret", agentidentity.EnabledTransports{HTTP: true})
	if err != nil {
		t.Fatalf("Agent record: %v", err)
	}
	if err := manager.Store(record); err != nil {
		t.Fatalf("store Agent: %v", err)
	}
	memory := ingestionauth.NewMemoryAudit()
	audit := ingestionauth.Audit(memory)
	if failure != nil {
		audit = failure
	}
	return ingestionauth.New(manager, audit, func() time.Time { return now }, 100, time.Minute), memory
}

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

func (f httpHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f(w, r)
}
