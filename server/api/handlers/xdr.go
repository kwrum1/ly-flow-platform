package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type XDREventResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    interface{}     `json:"data,omitempty"`
}

type XDREventListResponse struct {
	Items  interface{} `json:"items"`
	Total  int         `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type XDREventHandler struct {
	processor *XDROptions
}

type XDROptions struct {
	Processor interface{}
}

func NewXDREventHandler(processor interface{}) *XDREventHandler {
	return &XDREventHandler{
		processor: &XDROptions{Processor: processor},
	}
}

func (h *XDREventHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	stats := &models.XDREventStats{
		TopSources: map[string]int64{},
		TopSrcIPs:  map[string]int64{},
		Sources:    []string{},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(stats))
}

func (h *XDREventHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	limit := parseQueryInt(r, "limit", 50)
	offset := parseQueryInt(r, "offset", 0)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(XDREventListResponse{
		Items:  []*models.XDREvent{},
		Total:  0,
		Limit:  limit,
		Offset: offset,
	}))
}

func (h *XDREventHandler) GetEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if _, err := parsePathID(r.URL.Path); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid event ID")
		return
	}

	ErrorResponse(w, http.StatusNotFound, "XDR event not found")
}

func (h *XDREventHandler) GetSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse([]map[string]interface{}{}))
}

func (h *XDREventHandler) GetTopEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse([]map[string]interface{}{}))
}

func (h *XDREventHandler) ReceiveLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var input models.XDRLogInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	log, err := input.ToNormalizedLog()
	if err != nil {
		ErrorResponse(w, http.StatusBadRequest, "Invalid log data")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SuccessResponse(map[string]interface{}{
		"id":       log.ID,
		"received": true,
		"source":   log.Source,
	}))
}
