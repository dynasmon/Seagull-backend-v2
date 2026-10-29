package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentidentity"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	ingestv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/ingest/v1"
)

const (
	EventsPath  = "/v1/events"
	EventsRoute = "POST " + EventsPath

	InventoryPath  = "/v1/inventory"
	InventoryRoute = "POST " + InventoryPath

	StatusPath  = "/v1/status"
	StatusRoute = "POST " + StatusPath

	AssessmentsPath  = "/v1/assessments"
	AssessmentsRoute = "POST " + AssessmentsPath

	ContentType = "application/x-protobuf"

	CodeAtCapacity    = "gateway_at_capacity"
	CodeNotAdmitted   = "agent_not_admitted"
	CodeNotRegistered = "agent_not_registered"
)

// Which tenant an agent's telemetry belongs to, if the platform admits it at
// all. The gateway is told the answer rather than looking it up: the registry is
// a control-plane store and the ingest path reads no store per batch.
type Roster interface {
	Tenant(agentID string) (string, bool)
	Knows(agentID string) bool
}

type HandlerOptions struct {
	Admitter       *Admitter
	Roster         Roster
	Limiter        *ratelimit.Limiter
	Capacity       *Capacity
	Metrics        *Metrics
	MaxBodyBytes   int64
	PublishTimeout time.Duration
}

type InventoryHandlerOptions struct {
	Admitter       *InventoryAdmitter
	Roster         Roster
	Limiter        *ratelimit.Limiter
	Capacity       *Capacity
	Metrics        *InventoryMetrics
	MaxBodyBytes   int64
	PublishTimeout time.Duration
}

type StatusHandlerOptions struct {
	Admitter       *StatusAdmitter
	Roster         Roster
	Limiter        *ratelimit.Limiter
	Capacity       *Capacity
	Metrics        *StatusMetrics
	MaxBodyBytes   int64
	PublishTimeout time.Duration
}

type AssessmentHandlerOptions struct {
	Admitter       *AssessmentAdmitter
	Roster         Roster
	Limiter        *ratelimit.Limiter
	Capacity       *Capacity
	Metrics        *AssessmentMetrics
	MaxBodyBytes   int64
	PublishTimeout time.Duration
}

type gate struct {
	roster         Roster
	limiter        *ratelimit.Limiter
	capacity       *Capacity
	maxBodyBytes   int64
	publishTimeout time.Duration
}

type Handler struct {
	stream  stream
	weigher *weigher
	gate
}

func NewHandler(options HandlerOptions) (*Handler, error) {
	if options.Admitter == nil {
		return nil, errors.New("the ingest handler needs an admitter")
	}
	if options.Metrics == nil {
		return nil, errors.New("the ingest handler needs metrics")
	}
	return newHandler(eventStream{admitter: options.Admitter, metrics: options.Metrics}, gate{
		roster:         options.Roster,
		limiter:        options.Limiter,
		capacity:       options.Capacity,
		maxBodyBytes:   options.MaxBodyBytes,
		publishTimeout: options.PublishTimeout,
	})
}

func NewInventoryHandler(options InventoryHandlerOptions) (*Handler, error) {
	if options.Admitter == nil {
		return nil, errors.New("the inventory handler needs an admitter")
	}
	if options.Metrics == nil {
		return nil, errors.New("the inventory handler needs metrics")
	}
	return newHandler(inventoryStream{admitter: options.Admitter, metrics: options.Metrics}, gate{
		roster:         options.Roster,
		limiter:        options.Limiter,
		capacity:       options.Capacity,
		maxBodyBytes:   options.MaxBodyBytes,
		publishTimeout: options.PublishTimeout,
	})
}

func NewStatusHandler(options StatusHandlerOptions) (*Handler, error) {
	if options.Admitter == nil {
		return nil, errors.New("the status handler needs an admitter")
	}
	if options.Metrics == nil {
		return nil, errors.New("the status handler needs metrics")
	}
	return newHandler(statusStream{admitter: options.Admitter, metrics: options.Metrics}, gate{
		roster:         options.Roster,
		limiter:        options.Limiter,
		capacity:       options.Capacity,
		maxBodyBytes:   options.MaxBodyBytes,
		publishTimeout: options.PublishTimeout,
	})
}

func NewAssessmentHandler(options AssessmentHandlerOptions) (*Handler, error) {
	if options.Admitter == nil {
		return nil, errors.New("the assessment handler needs an admitter")
	}
	if options.Metrics == nil {
		return nil, errors.New("the assessment handler needs metrics")
	}
	return newHandler(assessmentStream{admitter: options.Admitter, metrics: options.Metrics}, gate{
		roster:         options.Roster,
		limiter:        options.Limiter,
		capacity:       options.Capacity,
		maxBodyBytes:   options.MaxBodyBytes,
		publishTimeout: options.PublishTimeout,
	})
}

func newHandler(admitting stream, standing gate) (*Handler, error) {
	if standing.roster == nil {
		return nil, errors.New("the ingest handler needs to know which agents the platform still honours")
	}
	if standing.maxBodyBytes <= 0 {
		return nil, errors.New("the ingest handler needs a positive body ceiling")
	}
	if standing.publishTimeout <= 0 {
		return nil, errors.New("the ingest handler needs a positive publish budget")
	}
	if standing.capacity == nil {
		return nil, errors.New("the ingest handler needs a ceiling on what the process holds at once")
	}
	if held, _ := standing.capacity.Bounds(); held < standing.maxBodyBytes {
		return nil, fmt.Errorf("the gateway holds %d bytes at once and admits a body of %d, so no batch could ever be taken",
			held, standing.maxBodyBytes)
	}
	scale, err := newWeigher(admitting.batch())
	if err != nil {
		return nil, fmt.Errorf("the %s route: %w", admitting.name(), err)
	}
	return &Handler{stream: admitting, weigher: scale, gate: standing}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identity, err := agentidentity.FromConnection(r.TLS)
	if err != nil {
		refuse(w, http.StatusForbidden, "unauthenticated_agent", err.Error(), "", -1)
		return
	}

	ctx := log.With(r.Context(), slog.String("agent_id", identity.AgentID))

	// A certificate says who an agent is, and the registry says whose estate its
	// telemetry belongs to and whether the platform still listens to it. The
	// answer is held in memory from a compacted topic, so it costs a map lookup
	// and no round trip, and an agent it names no tenant for is never placed in one.
	tenant, admitted := h.roster.Tenant(identity.AgentID)
	if !admitted {
		h.refuseUnadmitted(w, identity.AgentID)
		return
	}

	if !h.limiter.Allow(identity.AgentID) {
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusTooManyRequests, "rate_limited", "the agent is sending faster than this gateway admits", "", -1)
		return
	}

	if !protobufRequest(r) {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "batches are sent as "+ContentType, "", -1)
		return
	}

	reservation, admitted := h.capacity.Hold(h.reserving(r))
	if !admitted {
		h.refuseAtCapacity(w)
		return
	}
	defer reservation.Release()

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

	weight, err := h.weigher.weigh(payload)
	if err != nil {
		h.refuseAdmission(ctx, w, outcome{}, refuseMalformed(h.stream))
		return
	}
	holding := int64(len(payload)) + weight
	if bound, _ := h.capacity.Bounds(); holding > bound {
		h.refuseHeavy(ctx, w, len(payload), holding, bound)
		return
	}
	if !reservation.Resize(holding) {
		h.refuseAtCapacity(w)
		return
	}

	publishCtx, cancel := context.WithTimeout(ctx, h.publishTimeout)
	defer cancel()

	carried, err := h.stream.admit(publishCtx, identity, tenant, payload)
	if err != nil {
		h.refuseAdmission(ctx, w, carried, err)
		return
	}

	log.From(ctx).Info("batch_admitted",
		slog.String("stream", h.stream.name()),
		slog.String("batch_id", carried.batchID),
		slog.Int("records", carried.records),
	)
	respond(w, http.StatusOK, carried.acknowledgement)
}

func (h *Handler) refuseAtCapacity(w http.ResponseWriter) {
	h.stream.rejected(CodeAtCapacity)
	w.Header().Set("Retry-After", "1")
	refuse(w, http.StatusServiceUnavailable, CodeAtCapacity,
		"the gateway is holding as much work as it was bounded to", "", -1)
}

func (h *Handler) refuseHeavy(ctx context.Context, w http.ResponseWriter, body int, holding, bound int64) {
	h.stream.rejected(string(CodeBatchTooLarge))
	log.From(ctx).Warn("batch_rejected",
		slog.String("stream", h.stream.name()),
		slog.String("code", string(CodeBatchTooLarge)),
		slog.Int("body_bytes", body),
		slog.Int64("decoded_bytes", holding-int64(body)),
	)
	refuse(w, http.StatusRequestEntityTooLarge, string(CodeBatchTooLarge),
		fmt.Sprintf("decoding the batch would hold %d bytes and the gateway holds %d at once", holding, bound), "", -1)
}

func (h *Handler) refuseUnadmitted(w http.ResponseWriter, agentID string) {
	if !h.roster.Knows(agentID) {
		h.stream.rejected(CodeNotRegistered)
		refuse(w, http.StatusForbidden, CodeNotRegistered,
			"the platform has no registration for this agent, so its telemetry belongs to no tenant", "", -1)
		return
	}
	h.stream.rejected(CodeNotAdmitted)
	refuse(w, http.StatusForbidden, CodeNotAdmitted,
		"the platform no longer admits telemetry from this agent", "", -1)
}

func (h *Handler) refuseAdmission(ctx context.Context, w http.ResponseWriter, carried outcome, err error) {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		status := http.StatusUnprocessableEntity
		switch rejection.Code {
		case CodeUnsupportedProtocol:
			status = http.StatusUpgradeRequired
		case CodeMalformedPayload:
			status = http.StatusBadRequest
		}
		log.From(ctx).Warn("batch_rejected",
			slog.String("stream", h.stream.name()),
			slog.String("batch_id", carried.batchID),
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
		slog.String("stream", h.stream.name()),
		slog.String("batch_id", carried.batchID),
		slog.Int("records", carried.records),
		slog.String("error", err.Error()),
	)
	w.Header().Set("Retry-After", "5")
	refuse(w, http.StatusServiceUnavailable, "backbone_unavailable", "the batch was not made durable", "", -1)
}

// A body that lies about its length is stopped by the reader, so the
// reservation is never smaller than the allocation it stands for.
func (h *Handler) reserving(r *http.Request) int64 {
	if r.ContentLength <= 0 || r.ContentLength > h.maxBodyBytes {
		return h.maxBodyBytes
	}
	return r.ContentLength
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
