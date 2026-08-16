package ingest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
	"github.com/dynasmon/Seagull-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-v2/internal/platform/log"
)

const (
	EventsPath  = "/v1/events"
	EventsRoute = "POST " + EventsPath

	ContentType = "application/x-protobuf"
)

type HandlerOptions struct {
	Admitter       *Admitter
	Limiter        *Limiter
	MaxBodyBytes   int64
	PublishTimeout time.Duration
}

type Handler struct {
	admitter       *Admitter
	limiter        *Limiter
	maxBodyBytes   int64
	publishTimeout time.Duration
}

func NewHandler(options HandlerOptions) (*Handler, error) {
	if options.Admitter == nil {
		return nil, errors.New("the ingest handler needs an admitter")
	}
	if options.MaxBodyBytes <= 0 {
		return nil, errors.New("the ingest handler needs a positive body ceiling")
	}
	if options.PublishTimeout <= 0 {
		return nil, errors.New("the ingest handler needs a positive publish budget")
	}
	return &Handler{
		admitter:       options.Admitter,
		limiter:        options.Limiter,
		maxBodyBytes:   options.MaxBodyBytes,
		publishTimeout: options.PublishTimeout,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identity, err := agentidentity.FromConnection(r.TLS)
	if err != nil {
		refuse(w, http.StatusForbidden, "unauthenticated_agent", err.Error(), "", -1)
		return
	}

	ctx := log.With(r.Context(), slog.String("agent_id", identity.AgentID))

	if !h.limiter.Allow(identity.AgentID) {
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusTooManyRequests, "rate_limited", "the agent is sending faster than this gateway admits", "", -1)
		return
	}

	if !protobufRequest(r) {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "batches are sent as "+ContentType, "", -1)
		return
	}

	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			refuse(w, http.StatusRequestEntityTooLarge, "batch_body_too_large", "the batch body exceeds the gateway ceiling", "", -1)
			return
		}
		refuse(w, http.StatusBadRequest, "unreadable_body", "the batch body could not be read", "", -1)
		return
	}

	var batch ingestv1.EventBatch
	if err := proto.Unmarshal(payload, &batch); err != nil {
		refuse(w, http.StatusBadRequest, "malformed_payload", "the batch is not a valid protobuf message", "", -1)
		return
	}

	publishCtx, cancel := context.WithTimeout(ctx, h.publishTimeout)
	defer cancel()

	acknowledgement, err := h.admitter.Admit(publishCtx, identity, &batch)
	if err != nil {
		h.refuseAdmission(ctx, w, &batch, err)
		return
	}

	log.From(ctx).Info("batch_admitted",
		slog.String("batch_id", batch.GetBatchId()),
		slog.Int("events", len(batch.GetEvents())),
	)
	respond(w, http.StatusOK, acknowledgement)
}

func (h *Handler) refuseAdmission(ctx context.Context, w http.ResponseWriter, batch *ingestv1.EventBatch, err error) {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		status := http.StatusUnprocessableEntity
		if rejection.Code == CodeUnsupportedProtocol {
			status = http.StatusUpgradeRequired
		}
		log.From(ctx).Warn("batch_rejected",
			slog.String("batch_id", batch.GetBatchId()),
			slog.String("code", string(rejection.Code)),
			slog.String("field", rejection.Field),
			slog.Int("event_index", rejection.EventIndex),
		)
		refuse(w, status, string(rejection.Code), rejection.Detail, rejection.Field, rejection.EventIndex)
		return
	}

	// A batch the backbone did not accept is never acknowledged: the agent keeps
	// its copy and retries, which is the only reason its spool can be trusted.
	log.From(ctx).Error("batch_not_durable",
		slog.String("batch_id", batch.GetBatchId()),
		slog.Int("events", len(batch.GetEvents())),
		slog.String("error", err.Error()),
	)
	w.Header().Set("Retry-After", "5")
	refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "the batch was not made durable", "", -1)
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
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func refuse(w http.ResponseWriter, status int, code, detail, field string, index int) {
	respond(w, status, &ingestv1.Rejection{
		Code:       code,
		Detail:     detail,
		Field:      field,
		EventIndex: int32(index),
	})
}
