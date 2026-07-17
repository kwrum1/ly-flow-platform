package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
	"github.com/lyflow/ly-flow-platform/server/internal/redisconfig"
	"github.com/redis/go-redis/v9"
)

var ErrUnauthenticated = errors.New("websocket: authenticated principal required")

const agentMessageOversizeReason = "message exceeds 512-byte limit"

type Authorizer func(*http.Request) (string, error)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return originAllowed(r)
	},
}

// Hub maintains the set of active clients and broadcasts messages to them
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	authorize  Authorizer
	perUser    map[string]int
	maxPerUser int
	agentAuth  *ingestionauth.Authenticator
	messages   *principalMessageLimiter
}

// Client represents a WebSocket client
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	userID string
	agent  *ingestionauth.Principal
}

type AgentHubOptions struct {
	MessagesPerMinute int
	Now               func() time.Time
}

// NewHub creates a new Hub instance
func NewHub() *Hub {
	return NewAuthenticatedHub(func(*http.Request) (string, error) { return "", ErrUnauthenticated })
}

func NewAuthenticatedHub(authorize Authorizer) *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		authorize:  authorize,
		perUser:    make(map[string]int),
		maxPerUser: 4,
	}
}

func NewAgentHub(authenticator *ingestionauth.Authenticator, options AgentHubOptions) *Hub {
	limit := options.MessagesPerMinute
	if limit <= 0 {
		limit = 600
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	hub := NewHub()
	hub.agentAuth = authenticator
	hub.messages = newPrincipalMessageLimiter(limit, time.Minute, now)
	return hub
}

// Run starts the hub's main loop
func (h *Hub) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("WebSocket client connected: %s", client.userID)
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				h.decrementConnectionLocked(client.userID)
			}
			h.mu.Unlock()
			log.Printf("WebSocket client disconnected: %s", client.userID)
		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
					h.decrementConnectionLocked(client.userID)
				}
			}
			h.mu.Unlock()
		}
	}
}

// Broadcast sends a message to all connected clients
func (h *Hub) Broadcast(message []byte) {
	h.broadcast <- message
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// HandleWebSocket handles WebSocket upgrade requests
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	if h.agentAuth != nil {
		h.handleAgentWebSocket(w, r)
		return
	}
	if h.authorize == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	userID, err := h.authorize(r)
	if err != nil || strings.TrimSpace(userID) == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	userID = strings.TrimSpace(userID)
	if claimed := strings.TrimSpace(r.URL.Query().Get("user_id")); claimed != "" && claimed != userID {
		http.Error(w, "principal mismatch", http.StatusForbidden)
		return
	}
	if !h.reserveConnection(userID) {
		http.Error(w, "connection rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.releaseConnection(userID)
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID,
	}

	h.register <- client

	go client.writePump()
	client.readPump()
}

func (h *Hub) handleAgentWebSocket(w http.ResponseWriter, r *http.Request) {
	const surface = "websocket.agent"
	principal, err := h.agentAuth.HTTPPrincipal(r, surface)
	if err != nil {
		statusCode := http.StatusUnauthorized
		if ingestionauth.IsAuditUnavailable(err) {
			statusCode = http.StatusServiceUnavailable
		} else if ingestionauth.IsRateLimited(err) {
			statusCode = http.StatusTooManyRequests
		}
		http.Error(w, http.StatusText(statusCode), statusCode)
		return
	}
	if !originAllowed(r) {
		if err := h.agentAuth.Record(r.Context(), principal, surface, ingestionauth.OutcomeRejected, "origin rejected"); err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if !h.reserveConnection(principal.AgentID()) {
		if err := h.agentAuth.Record(r.Context(), principal, surface, ingestionauth.OutcomeRateLimited, "connection limit exceeded"); err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	if err := h.agentAuth.Record(r.Context(), principal, surface, ingestionauth.OutcomeAccepted, "connection opened"); err != nil {
		h.releaseConnection(principal.AgentID())
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.releaseConnection(principal.AgentID())
		return
	}
	client := &Client{hub: h, conn: conn, send: make(chan []byte, 256), userID: principal.AgentID(), agent: &principal}
	h.register <- client
	go client.writePump()
	client.readPump()
}

func originAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && strings.EqualFold(parsed.Host, r.Host)
}

func (h *Hub) reserveConnection(userID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.perUser[userID] >= h.maxPerUser {
		return false
	}
	h.perUser[userID]++
	return true
}

func (h *Hub) releaseConnection(userID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.decrementConnectionLocked(userID)
}

func (h *Hub) decrementConnectionLocked(userID string) {
	h.perUser[userID]--
	if h.perUser[userID] <= 0 {
		delete(h.perUser, userID)
	}
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		if c.agent != nil {
			if err := c.hub.agentAuth.Record(context.Background(), *c.agent, "websocket.agent", ingestionauth.OutcomeClosed, "connection closed"); err != nil {
				c.writeAuditFailureClose()
			}
		}
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			c.handleReadError(err)
			break
		}
		if c.agent != nil && !c.hub.messages.Allow(c.agent.AgentID()) {
			code := websocket.ClosePolicyViolation
			reason := "message rate limit exceeded"
			if err := c.hub.agentAuth.Record(context.Background(), *c.agent, "websocket.agent", ingestionauth.OutcomeRateLimited, reason); err != nil {
				code = websocket.CloseInternalServerErr
				reason = "lifecycle audit unavailable"
			}
			_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
			break
		}
	}
}

func (c *Client) handleReadError(err error) {
	if errors.Is(err, websocket.ErrReadLimit) {
		if c.agent != nil {
			if auditErr := c.hub.agentAuth.Record(context.Background(), *c.agent, "websocket.agent", ingestionauth.OutcomeRejected, agentMessageOversizeReason); auditErr != nil {
				c.writeAuditFailureClose()
			}
		}
		return
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		if closeErr.Code != websocket.CloseNormalClosure && closeErr.Code != websocket.CloseGoingAway && closeErr.Code != websocket.CloseAbnormalClosure {
			log.Printf("WebSocket peer close: code=%d", closeErr.Code)
		}
		return
	}
	log.Printf("WebSocket read failed")
}

func (c *Client) writeAuditFailureClose() {
	message := websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "lifecycle audit unavailable")
	if err := c.conn.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second)); err != nil {
		log.Printf("WebSocket lifecycle audit persistence failed; connection already closing")
		return
	}
	log.Printf("WebSocket lifecycle audit persistence failed")
}

type principalMessageLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	buckets map[string]messageBucket
}

type messageBucket struct {
	start time.Time
	count int
}

func newPrincipalMessageLimiter(limit int, window time.Duration, now func() time.Time) *principalMessageLimiter {
	return &principalMessageLimiter{limit: limit, window: window, now: now, buckets: make(map[string]messageBucket)}
}

func (l *principalMessageLimiter) Allow(principalID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	bucket := l.buckets[principalID]
	if bucket.start.IsZero() || now.Sub(bucket.start) >= l.window {
		l.buckets[principalID] = messageBucket{start: now, count: 1}
		return true
	}
	if bucket.count >= l.limit {
		return false
	}
	bucket.count++
	l.buckets[principalID] = bucket
	return true
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Response represents a standard API response
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// NewResponse creates a new API response
func NewResponse(code int, message string, data interface{}) Response {
	return Response{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

// SuccessResponse returns a successful response
func SuccessResponse(data interface{}) Response {
	return NewResponse(0, "success", data)
}

// RedisPubSub subscribes to Redis Pub/Sub for real-time alert notifications
type RedisPubSub struct {
	client *redis.Client
	hub    *Hub
	stopCh chan struct{}
}

// NewRedisPubSub creates a new Redis Pub/Sub subscriber
func NewRedisPubSub(redisAddr string, hub *Hub) (*RedisPubSub, error) {
	client := redis.NewClient(redisconfig.Options(redisAddr, 1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisPubSub{
		client: client,
		hub:    hub,
		stopCh: make(chan struct{}),
	}, nil
}

// Start begins subscribing to the alerts:new channel
func (r *RedisPubSub) Start(ctx context.Context) {
	go r.subscribe(ctx)
}

// Stop stops the Pub/Sub subscription
func (r *RedisPubSub) Stop() {
	close(r.stopCh)
	r.client.Close()
}

func (r *RedisPubSub) subscribe(ctx context.Context) {
	pubsub := r.client.Subscribe(ctx, "alerts:new")
	defer pubsub.Close()

	ch := pubsub.Channel()
	log.Println("Redis PubSub subscribed to alerts:new")

	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case msg := <-ch:
			if msg != nil {
				r.hub.Broadcast([]byte(msg.Payload))
			}
		}
	}
}

// NotifyNewAlert publishes a new alert notification to Redis
func NotifyNewAlert(redisAddr string, alert interface{}) error {
	client := redis.NewClient(redisconfig.Options(redisAddr, 1))
	defer client.Close()

	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return client.Publish(ctx, "alerts:new", data).Err()
}

// ParseLimitOffset parses limit and offset from request
func ParseLimitOffset(r *http.Request, defaultLimit, maxLimit int) (int, int) {
	limit := defaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
			if limit > maxLimit {
				limit = maxLimit
			}
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	return limit, offset
}
