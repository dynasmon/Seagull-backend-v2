package hunt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

const (
	EventsPath  = "/v1/hunt/events"
	EventsRoute = "POST " + EventsPath

	DetectionsPath  = "/v1/hunt/detections"
	DetectionsRoute = "POST " + DetectionsPath

	ContentType = "application/x-protobuf"

	CodeAtCapacity  = "query_plane_at_capacity"
	CodeRateLimited = "rate_limited"
	CodeForbidden   = "forbidden"
)

type HandlerOptions struct {
	Grants       Grants
	Hunter       *Hunter
	Lister       *Lister
	Capacity     *Capacity
	Limiter      *ratelimit.Limiter
	Metrics      *Metrics
	MaxBodyBytes int64
}

type Handler struct {
	grants       Grants
	capacity     *Capacity
	limiter      *ratelimit.Limiter
	metrics      *Metrics
	maxBodyBytes int64
	dataset      Dataset
	route        route
}

func NewHandler(dataset Dataset, options HandlerOptions) (*Handler, error) {
	switch {
	case options.Grants == nil:
		return nil, errors.New("the hunt handler needs the policy that says who may ask what")
	case options.MaxBodyBytes <= 0:
		return nil, errors.New("the hunt handler needs a positive body ceiling")
	case options.Capacity == nil:
		return nil, errors.New("the hunt handler needs a ceiling on what the process holds at once")
	case options.Metrics == nil:
		return nil, errors.New("the hunt handler needs metrics")
	}
	served, err := routeOf(dataset, options)
	if err != nil {
		return nil, err
	}
	return &Handler{
		grants:       options.Grants,
		capacity:     options.Capacity,
		limiter:      options.Limiter,
		metrics:      options.Metrics,
		maxBodyBytes: options.MaxBodyBytes,
		dataset:      dataset,
		route:        served,
	}, nil
}

// What a route reads its question as and who answers it. Every route shares the
// admission above it, so a listing is authorised, limited and held to the
// process ceiling exactly as a hunt is.
type route struct {
	question func() proto.Message
	answer   func(ctx context.Context, scope Scope, asked proto.Message) (proto.Message, error)
}

func asking[Q any, PQ interface {
	*Q
	proto.Message
}, A proto.Message](answer func(context.Context, Scope, PQ) (A, error)) route {
	return route{
		question: func() proto.Message { return PQ(new(Q)) },
		answer: func(ctx context.Context, scope Scope, asked proto.Message) (proto.Message, error) {
			return answer(ctx, scope, asked.(PQ))
		},
	}
}

func routeOf(dataset Dataset, options HandlerOptions) (route, error) {
	switch {
	case Known(dataset) && options.Hunter == nil:
		return route{}, errors.New("the hunt handler needs a hunter")
	case dataset == Events:
		return asking(options.Hunter.Events), nil
	case dataset == Detections:
		return asking(options.Hunter.Detections), nil
	case listed(dataset) && options.Lister == nil:
		return route{}, fmt.Errorf("the %s handler needs a lister", dataset)
	}
	switch dataset {
	case Assets:
		return asking(options.Lister.Assets), nil
	case Items:
		return asking(options.Lister.Items), nil
	case Findings:
		return asking(options.Lister.Findings), nil
	case FindingHistory:
		return asking(options.Lister.History), nil
	case Assessments:
		return asking(options.Lister.Assessments), nil
	case Advisories:
		return asking(options.Lister.Advisories), nil
	}
	return route{}, errors.New("the hunt handler needs a dataset it can ask about")
}

// Authorisation is decided before the body is read, and the scope it produces is
// the only thing that decides which tenants the answer can come from. There is
// no query parameter and no header that widens it. What the caller may spend is
// decided next and still before the body: a share of the process per certificate
// and a ceiling on the whole of it, so one analyst asking expensive questions
// cannot become every analyst waiting.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scope, err := Authorize(r.TLS, h.grants, h.dataset)
	if err != nil {
		code := CodeUnscoped
		if errors.Is(err, ErrNotGranted) || errors.Is(err, ErrNotPermitted) {
			code = CodeForbidden
		}
		h.metrics.refused(h.dataset, code)
		refuse(w, http.StatusForbidden, code, err.Error(), "")
		return
	}

	caller := CallerFromConnection(r.TLS)
	ctx := log.With(r.Context(), slog.String("caller", caller))

	if !h.limiter.Allow(caller) {
		h.metrics.refused(h.dataset, CodeRateLimited)
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusTooManyRequests, CodeRateLimited, "this caller is asking faster than the query plane answers", "")
		return
	}

	release, admitted := h.capacity.Hold()
	if !admitted {
		h.metrics.refused(h.dataset, CodeAtCapacity)
		w.Header().Set("Retry-After", "1")
		refuse(w, http.StatusServiceUnavailable, CodeAtCapacity,
			"the query plane is holding as many questions as it was bounded to", "")
		return
	}
	defer release()

	asked := h.route.question()
	if !h.read(w, r, asked) {
		return
	}

	page, err := h.route.answer(ctx, scope, asked)
	if err != nil {
		h.refuseQuery(ctx, w, err)
		return
	}
	respond(w, http.StatusOK, page)
}

func (h *Handler) read(w http.ResponseWriter, r *http.Request, asked proto.Message) bool {
	if !protobufRequest(r) {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "a query is sent as "+ContentType, "")
		return false
	}

	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			refuse(w, http.StatusRequestEntityTooLarge, "query_body_too_large", "the query body exceeds the ceiling", "")
			return false
		}
		refuse(w, http.StatusBadRequest, "unreadable_body", "the query body could not be read", "")
		return false
	}

	if err := proto.Unmarshal(payload, asked); err != nil {
		refuse(w, http.StatusBadRequest, "malformed_payload", "the query is not a valid protobuf message", "")
		return false
	}
	return true
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
