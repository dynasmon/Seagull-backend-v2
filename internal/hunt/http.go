package hunt

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

const (
	EventsPath  = "/v1/hunt/events"
	EventsRoute = "POST " + EventsPath

	DetectionsPath  = "/v1/hunt/detections"
	DetectionsRoute = "POST " + DetectionsPath

	ContentType = "application/x-protobuf"
)

type HandlerOptions struct {
	Hunter       *Hunter
	MaxBodyBytes int64
}

type Handler struct {
	hunter       *Hunter
	maxBodyBytes int64
	dataset      Dataset
}

func NewHandler(dataset Dataset, options HandlerOptions) (*Handler, error) {
	switch {
	case options.Hunter == nil:
		return nil, errors.New("the hunt handler needs a hunter")
	case options.MaxBodyBytes <= 0:
		return nil, errors.New("the hunt handler needs a positive body ceiling")
	case !Known(dataset):
		return nil, errors.New("the hunt handler needs a dataset it can ask about")
	}
	return &Handler{hunter: options.Hunter, maxBodyBytes: options.MaxBodyBytes, dataset: dataset}, nil
}

// Authorisation is decided before the body is read, and the scope it produces is
// the only thing that decides which tenants the answer can come from. There is
// no query parameter and no header that widens it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scope, err := ScopeFromConnection(r.TLS)
	if err != nil {
		refuse(w, http.StatusForbidden, CodeUnscoped, err.Error(), "")
		return
	}

	ctx := log.With(r.Context(), slog.String("caller", CallerFromConnection(r.TLS)))

	asked, ok := h.read(w, r)
	if !ok {
		return
	}

	switch h.dataset {
	case Detections:
		page, err := h.hunter.Detections(ctx, scope, asked)
		if err != nil {
			h.refuseQuery(ctx, w, err)
			return
		}
		respond(w, http.StatusOK, page)
	default:
		page, err := h.hunter.Events(ctx, scope, asked)
		if err != nil {
			h.refuseQuery(ctx, w, err)
			return
		}
		respond(w, http.StatusOK, page)
	}
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request) (*huntv1.Query, bool) {
	if !protobufRequest(r) {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "a query is sent as "+ContentType, "")
		return nil, false
	}

	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			refuse(w, http.StatusRequestEntityTooLarge, "query_body_too_large", "the query body exceeds the ceiling", "")
			return nil, false
		}
		refuse(w, http.StatusBadRequest, "unreadable_body", "the query body could not be read", "")
		return nil, false
	}

	var asked huntv1.Query
	if err := proto.Unmarshal(payload, &asked); err != nil {
		refuse(w, http.StatusBadRequest, "malformed_payload", "the query is not a valid protobuf message", "")
		return nil, false
	}
	return &asked, true
}

// A question this plane would not put to the store is the caller's to correct; a
// store that could not answer one it accepted is the platform's, and the caller
// is told to come back rather than told the query was wrong.
func (h *Handler) refuseQuery(ctx context.Context, w http.ResponseWriter, err error) {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		status := http.StatusUnprocessableEntity
		if refusal.Code == CodeUnscoped {
			status = http.StatusForbidden
		}
		log.From(ctx).Warn("hunt_refused",
			slog.String("dataset", string(h.dataset)),
			slog.String("code", refusal.Code),
			slog.String("field", refusal.Field),
		)
		refuse(w, status, refusal.Code, refusal.Detail, refusal.Field)
		return
	}

	status, code := http.StatusServiceUnavailable, "store_unavailable"
	if errors.Is(err, context.DeadlineExceeded) {
		status, code = http.StatusGatewayTimeout, "store_too_slow"
	}
	log.From(ctx).Error("hunt_unanswered",
		slog.String("dataset", string(h.dataset)),
		slog.String("error", err.Error()),
	)
	w.Header().Set("Retry-After", "5")
	refuse(w, status, code, "the store did not answer this query", "")
}

func protobufRequest(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return mediaType == ContentType || mediaType == "application/protobuf"
}

func respond(w http.ResponseWriter, status int, message proto.Message) {
	encoded, err := proto.Marshal(message)
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func refuse(w http.ResponseWriter, status int, code, detail, field string) {
	respond(w, status, &huntv1.Refusal{Code: code, Detail: detail, Field: field})
}
