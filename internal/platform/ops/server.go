package ops

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/health"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
)

type Options struct {
	Service         string
	Address         string
	Health          *health.Registry
	Metrics         *metrics.Registry
	Instrumentation *httpx.Instrumentation
	Logger          *slog.Logger
	ShutdownTimeout time.Duration
}

func NewServer(options Options) (*httpx.Server, error) {
	if options.Instrumentation == nil {
		return nil, errors.New("the operational server shares the process http instrumentation")
	}
	instrumentation := options.Instrumentation
	readiness := &readinessHandler{registry: options.Health, logger: options.Logger}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", instrumentation.Handle("healthz", http.HandlerFunc(liveness)))
	mux.Handle("GET /readyz", instrumentation.Handle("readyz", readiness))
	mux.Handle("GET /metrics", instrumentation.Handle("metrics", options.Metrics.Handler()))

	return httpx.NewServer(httpx.ServerOptions{
		Name:              "ops",
		Address:           options.Address,
		Handler:           mux,
		Logger:            options.Logger,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   options.ShutdownTimeout,
		MaxHeaderBytes:    16 << 10,
	})
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	writeStatus(w, http.StatusOK, string(health.StatusOK))
}

type readinessHandler struct {
	registry *health.Registry
	logger   *slog.Logger

	mu   sync.Mutex
	last health.Status
}

// The body carries a verdict and nothing else: readiness is reachable from the
// operational network, and a component-by-component report describes the
// platform's topology and failure modes to anyone who can call it.
func (h *readinessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	report := h.registry.Readiness(r.Context())
	h.recordTransition(report)

	status := http.StatusOK
	if !report.Ready() {
		status = http.StatusServiceUnavailable
		w.Header().Set("Retry-After", "5")
	}
	writeStatus(w, status, string(report.Status))
}

func (h *readinessHandler) recordTransition(report health.Report) {
	h.mu.Lock()
	changed := h.last != report.Status
	h.last = report.Status
	h.mu.Unlock()
	if !changed {
		return
	}

	attributes := []any{slog.String("status", string(report.Status))}
	for _, component := range report.Components {
		if component.Status != health.StatusOK {
			attributes = append(attributes, slog.String("degraded."+component.Name, component.Failure))
		}
	}
	if report.Ready() {
		h.logger.Info("readiness_changed", attributes...)
		return
	}
	h.logger.Warn("readiness_changed", attributes...)
}

func writeStatus(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}
