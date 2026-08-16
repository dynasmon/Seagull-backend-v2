package httpx

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/dynasmon/Seagull-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-v2/internal/platform/metrics"
)

type Instrumentation struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	panics   *prometheus.CounterVec
}

func NewInstrumentation(registry *metrics.Registry) *Instrumentation {
	instrumentation := &Instrumentation{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "HTTP requests served, by route and status class.",
		}, []string{"route", "method", "status_class"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "Time spent serving an HTTP request, by route.",
			Buckets:   []float64{0.005, 0.025, 0.1, 0.25, 1, 5, 30},
		}, []string{"route"}),
		panics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "http",
			Name:      "handler_panics_total",
			Help:      "Handlers that terminated with a panic.",
		}, []string{"route"}),
	}
	registry.MustRegister(instrumentation.requests, instrumentation.duration, instrumentation.panics)
	return instrumentation
}

type recorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *recorder) WriteHeader(status int) {
	if r.written {
		return
	}
	r.status = status
	r.written = true
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(payload []byte) (int, error) {
	if !r.written {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(payload)
}

func statusClass(status int) string {
	switch {
	case status >= 500:
		return "5xx"
	case status >= 400:
		return "4xx"
	case status >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// The request identifier is always minted here: an identifier taken from the
// request would let a caller choose what appears in the platform's logs.
func requestID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "unidentified"
	}
	return hex.EncodeToString(raw)
}

func (i *Instrumentation) Handle(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		tracked := &recorder{ResponseWriter: w, status: http.StatusOK}

		ctx := log.With(r.Context(),
			slog.String("request_id", requestID()),
			slog.String("route", route),
		)
		request := r.WithContext(ctx)

		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				i.panics.WithLabelValues(route).Inc()
				log.From(ctx).Error("handler_panic",
					slog.Any("panic", recovered),
					slog.String("method", r.Method),
				)
				if !tracked.written {
					http.Error(tracked, "internal error", http.StatusInternalServerError)
				}
			}

			elapsed := time.Since(started)
			i.requests.WithLabelValues(route, r.Method, statusClass(tracked.status)).Inc()
			i.duration.WithLabelValues(route).Observe(elapsed.Seconds())

			entry := log.From(ctx)
			attributes := []any{
				slog.String("method", r.Method),
				slog.Int("status", tracked.status),
				slog.Duration("elapsed", elapsed),
			}
			switch {
			case tracked.status >= 500:
				entry.Error("request_failed", attributes...)
			case tracked.status >= 400:
				entry.Warn("request_rejected", attributes...)
			default:
				entry.Debug("request_served", attributes...)
			}
		}()

		next.ServeHTTP(tracked, request)
	})
}
