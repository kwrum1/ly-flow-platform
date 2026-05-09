package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ly-flow-platform/server/api/websocket"
	"ly-flow-platform/server/models"
)

// Handler holds dependencies for API handlers
type Handler struct {
	DB        *models.DB
	WsHub     *websocket.Hub
	RedisAddr string
}

// NewHandler creates a new Handler instance
func NewHandler(db *models.DB, wsHub *websocket.Hub, redisAddr string) *Handler {
	return &Handler{
		DB:        db,
		WsHub:     wsHub,
		RedisAddr: redisAddr,
	}
}

// Response represents a standard API response
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ListResponse represents a paginated list response
type ListResponse struct {
	Items  interface{} `json:"items"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
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

// ErrorResponse sends an error response
func ErrorResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(NewResponse(1, message, nil))
}

// parseQueryInt parses a query parameter as int
func parseQueryInt(r *http.Request, key string, defaultVal int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return i
}

// parsePathID parses the last path segment as int64
func parsePathID(path string) (int64, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return 0, nil
	}
	idStr := parts[len(parts)-1]
	return strconv.ParseInt(idStr, 10, 64)
}

// HealthCheck handles GET /api/v1/health
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "ly-server",
		"version":   "v2.0.0",
	})
}

// ListEvents handles GET /api/v1/events
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	limit := parseQueryInt(r, "limit", 50)
	offset := parseQueryInt(r, "offset", 0)

	filters := make(map[string]interface{})
	filters["severity"] = r.URL.Query().Get("severity")
	filters["event_type"] = r.URL.Query().Get("event_type")
	filters["status"] = r.URL.Query().Get("status")
	filters["src_ip"] = r.URL.Query().Get("src_ip")
	filters["dst_ip"] = r.URL.Query().Get("dst_ip")

	events, total, err := h.DB.GetEvents(r.Context(), limit, offset, filters)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve events")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(ListResponse{
		Items:  events,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}))
}

// GetEvent handles GET /api/v1/events/{id}
func (h *Handler) GetEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id, err := parsePathID(r.URL.Path)
	if err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid event ID")
		return
	}

	event, err := h.DB.GetEventByID(r.Context(), id)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Event not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(event))
}

// SearchRequest represents a search request
type SearchRequest struct {
	Query     string   `json:"query"`
	Severity  string   `json:"severity,omitempty"`
	EventType string   `json:"event_type,omitempty"`
	Status    string   `json:"status,omitempty"`
	SrcIP     string   `json:"src_ip,omitempty"`
	DstIP     string   `json:"dst_ip,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Limit     int      `json:"limit,omitempty"`
	Offset    int      `json:"offset,omitempty"`
}

// SearchEvents handles POST /api/v1/events/search
func (h *Handler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	filters := make(map[string]interface{})
	if req.Severity != "" {
		filters["severity"] = req.Severity
	}
	if req.EventType != "" {
		filters["event_type"] = req.EventType
	}
	if req.Status != "" {
		filters["status"] = req.Status
	}
	if req.SrcIP != "" {
		filters["src_ip"] = req.SrcIP
	}
	if req.DstIP != "" {
		filters["dst_ip"] = req.DstIP
	}

	events, total, err := h.DB.GetEvents(r.Context(), req.Limit, req.Offset, filters)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Search failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(ListResponse{
		Items:  events,
		Total:  total,
		Limit:  req.Limit,
		Offset: req.Offset,
	}))
}

// ListAssets handles GET /api/v1/assets
func (h *Handler) ListAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	limit := parseQueryInt(r, "limit", 50)
	offset := parseQueryInt(r, "offset", 0)

	assets, total, err := h.DB.GetAssets(r.Context(), limit, offset)
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve assets")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(ListResponse{
		Items:  assets,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}))
}

// GetAsset handles GET /api/v1/assets/{id}
func (h *Handler) GetAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id, err := parsePathID(r.URL.Path)
	if err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid asset ID")
		return
	}

	asset, err := h.DB.GetAssetByID(r.Context(), id)
	if err != nil {
		ErrorResponse(w, http.StatusNotFound, "Asset not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(asset))
}

// GetStats handles GET /api/v1/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	stats, err := h.DB.GetStats(r.Context())
	if err != nil {
		ErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve stats")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(stats))
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// Login handles POST /api/v1/auth/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Simple authentication (replace with real auth in production)
	if req.Username == "admin" && req.Password == "admin123" {
		token := "lyflow-jwt-token-" + time.Now().Format("20060102150405")
		expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SuccessResponse(LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt,
		}))
		return
	}

	ErrorResponse(w, http.StatusUnauthorized, "Invalid credentials")
}

// TestWebhook handles POST /api/v1/webhook/test
type WebhookTestRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (h *Handler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req WebhookTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.URL == "" {
		ErrorResponse(w, http.StatusBadRequest, "URL is required")
		return
	}

	// Simulate webhook test
	testPayload := map[string]interface{}{
		"event":     "test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"status":    "ok",
		"service":   "ly-server",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(map[string]interface{}{
		"webhook_url": req.URL,
		"status":      "sent",
		"payload":     testPayload,
		"response":    "200 OK",
	}))
}