package unified

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ListResponse struct {
	Items  interface{} `json:"items"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

func SuccessResponse(data interface{}) Response {
	return Response{Code: 0, Message: "success", Data: data}
}

func ErrorResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{Code: status, Message: message})
}

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

func parseQueryString(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

func parsePathID(path string) int64 {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 {
		return 0
	}
	idStr := parts[len(parts)-1]
	id, _ := strconv.ParseInt(idStr, 10, 64)
	return id
}

func parseQueryBool(r *http.Request, key string, defaultVal bool) bool {
	val := r.URL.Query().Get(key)
	switch val {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return defaultVal
	}
}

func parseQueryTime(r *http.Request, key string) *time.Time {
	val := r.URL.Query().Get(key)
	if val == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil
	}
	return &t
}

func parseModules(r *http.Request) []ModuleType {
	modules := r.URL.Query()["module"]
	result := make([]ModuleType, 0, len(modules))
	for _, m := range modules {
		result = append(result, ModuleType(m))
	}
	return result
}

func parseSeverities(r *http.Request) []Severity {
	sev := r.URL.Query()["severity"]
	result := make([]Severity, 0, len(sev))
	for _, s := range sev {
		result = append(result, Severity(s))
	}
	return result
}

// GetStats 处理 GET /api/v1/unified/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	stats := &EventStats{
		ByModule:   map[ModuleType]int64{},
		BySeverity: map[Severity]int64{},
		BySource:   map[string]int64{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(stats))
}

// ListEvents 处理 GET /api/v1/unified/events
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	limit := parseQueryInt(r, "limit", 50)
	offset := parseQueryInt(r, "offset", 0)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(ListResponse{
		Items:  []*UnifiedEvent{},
		Total:  0,
		Limit:  limit,
		Offset: offset,
	}))
}

// GetEvent 处理 GET /api/v1/unified/events/{id}
func (h *Handler) GetEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := parsePathID(r.URL.Path)
	if id == 0 {
		ErrorResponse(w, http.StatusBadRequest, "Invalid event ID")
		return
	}

	ErrorResponse(w, http.StatusNotFound, "event not found")
}

// SearchEvents 处理 POST /api/v1/unified/events/search
func (h *Handler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var search EventSearch
	if err := json.NewDecoder(r.Body).Decode(&search); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if search.Limit == 0 {
		search.Limit = 50
	}
	if search.Offset == 0 {
		search.Offset = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(ListResponse{
		Items:  []*UnifiedEvent{},
		Total:  0,
		Limit:  search.Limit,
		Offset: search.Offset,
	}))
}

// UpdateEventStatus 处理 PUT /api/v1/unified/events/{id}/status
func (h *Handler) UpdateEventStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	id := parsePathID(r.URL.Path)
	if id == 0 {
		ErrorResponse(w, http.StatusBadRequest, "Invalid event ID")
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(map[string]interface{}{
		"id":     id,
		"status": req.Status,
	}))
}
