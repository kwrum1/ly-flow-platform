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
	// FieldMode controls network five-tuple enforcement. Empty means off so an
	// existing deployment keeps its behaviour until the operator opts in.
	FieldMode contracts.FieldValidationMode
	// Logf receives shadow-mode diagnostics; nil disables logging.
	Logf func(format string, args ...any)
	// TenantID is the server-side tenant every event is bound to. Client-supplied
	// tenant_id is treated as untrusted and overwritten.
	TenantID string
	// Tenant optionally resolves the tenant for an authenticated principal.
	Tenant func(*http.Request, string) (string, error)
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

	// Tenant is resolved server-side. A client-provided tenant_id is never
	// trusted: it would allow cross-tenant event injection.
	tenant := strings.TrimSpace(handler.TenantID)
	if handler.Tenant != nil {
		resolved, err := handler.Tenant(request, principalID)
		if err != nil {
			writeError(writer, http.StatusForbidden, "tenant_unresolved", "ingestion tenant unavailable")
			return
		}
		if strings.TrimSpace(resolved) != "" {
			tenant = strings.TrimSpace(resolved)
		}
	}
	if tenant == "" {
		tenant = "default"
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
		// Always overwrite: the authenticated tenant wins over client input.
		event.TenantID = tenant
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
		if err := event.ValidateWithMode(handler.FieldMode); err != nil {
			var violation *contracts.ContractValidationError
			if errors.As(err, &violation) {
				writeValidationError(writer, index, violation)
				return
			}
			writeError(writer, http.StatusBadRequest, "invalid_event", eventErrorMessage(index, err))
			return
		}
		if handler.FieldMode != "" && handler.FieldMode != contracts.FieldValidationOff {
			report := event.ApplyNetworkFieldFlags()
			if !report.Complete && handler.FieldMode == contracts.FieldValidationShadow && handler.Logf != nil {
				handler.Logf("eventv2 shadow: index=%d uid=%s gap=%s", index, event.EventUID, report.String())
			}
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

func writeValidationError(writer http.ResponseWriter, index int, violation *contracts.ContractValidationError) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"code":       http.StatusUnprocessableEntity,
		"error_code": violation.Code,
		"message":    "event[" + strconv.Itoa(index) + "]: " + violation.Error(),
		"field":      violation.Field,
		"reason":     violation.Reason,
	})
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
