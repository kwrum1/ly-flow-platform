package ingestv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

var ErrAuthUnavailable = errors.New("ingestion auth unavailable")

const (
	DefaultMaxBodyBytes = int64(4 << 20)
	DefaultMaxBatch     = 1000
	AuthSurface         = "ingest.v2"
)

// AuthFunc authenticates an ingestion request and returns the principal ID.
type AuthFunc func(*http.Request, string) (string, error)

// Writer persists validated v2 events.
type Writer interface {
	WriteEventsV2(context.Context, []contracts.EventV2) error
}

type Handler struct {
	Auth         AuthFunc
	Writer       Writer
	MaxBodyBytes int64
	MaxBatch     int
	Now          func() time.Time
}

type batchRequest struct {
	Events []contracts.EventV2 `json:"events"`
}

type batchResponse struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (handler Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}
	if handler.Auth == nil {
		writeError(writer, http.StatusServiceUnavailable, "auth_unavailable", "ingestion auth unavailable")
		return
	}
	principalID, err := handler.Auth(request, AuthSurface)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid ingestion credential required")
		return
	}
	if strings.TrimSpace(principalID) == "" {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "empty ingestion principal")
		return
	}

	maxBody := handler.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maxBody))
	var payload batchRequest
	if err := decoder.Decode(&payload); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json", "invalid event batch")
		return
	}
	maxBatch := handler.MaxBatch
	if maxBatch <= 0 {
		maxBatch = DefaultMaxBatch
	}
	if len(payload.Events) == 0 {
		writeError(writer, http.StatusBadRequest, "empty_batch", "at least one event is required")
		return
	}
	if len(payload.Events) > maxBatch {
		writeError(writer, http.StatusRequestEntityTooLarge, "batch_too_large", "event batch exceeds limit")
		return
	}

	now := time.Now().UTC()
	if handler.Now != nil {
		now = handler.Now().UTC()
	}
	for index := range payload.Events {
		event := &payload.Events[index]
		if event.TenantID == "" {
			event.TenantID = "default"
		}
		if event.CorrelationID == "" {
			event.CorrelationID = event.EventUID
		}
		if event.Entities.Asset == nil {
			event.Entities.Asset = &contracts.AssetEntity{ID: principalID}
		} else if event.Entities.Asset.ID == "" {
			event.Entities.Asset.ID = principalID
		}
		if event.Timestamps.IngestedAt.IsZero() {
			event.Timestamps.IngestedAt = now
		}
		if len(event.Payload) > 0 && event.Raw.PayloadSHA256 == "" {
			digest := sha256.Sum256(event.Payload)
			event.Raw.PayloadSHA256 = hex.EncodeToString(digest[:])
		}
		if err := event.Validate(); err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_event", eventErrorMessage(index, err))
			return
		}
	}

	if handler.Writer == nil {
		writeError(writer, http.StatusServiceUnavailable, "writer_unavailable", "event writer unavailable")
		return
	}
	if err := handler.Writer.WriteEventsV2(request.Context(), payload.Events); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "write_failed", "event storage unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, batchResponse{
		Code: 0, Message: "success",
		Data: map[string]any{"accepted": len(payload.Events)},
	})
}

func eventErrorMessage(index int, err error) string {
	if err == nil {
		return ""
	}
	return "event[" + strconv.Itoa(index) + "]: " + err.Error()
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code": status, "error_code": code, "message": message,
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
