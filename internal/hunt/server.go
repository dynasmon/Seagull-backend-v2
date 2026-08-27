package hunt

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
)

type ServerOptions struct {
	Address         string
	TLS             *tls.Config
	Hunter          *Hunter
	Instrumentation *httpx.Instrumentation
	Logger          *slog.Logger
	MaxBodyBytes    int64
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// A dataset gets a route rather than a field of the query, so a page of events
// and a page of detections are different messages and a caller cannot be handed
// one where it expected the other.
func NewServer(options ServerOptions) (*httpx.Server, error) {
	if options.Hunter == nil {
		return nil, errors.New("the hunt listener needs a hunter")
	}
	if options.Instrumentation == nil {
		return nil, errors.New("the hunt listener shares the process http instrumentation")
	}
	if options.TLS == nil {
		return nil, errors.New("the hunt listener authorises a caller by certificate and cannot serve without one")
	}

	mux := http.NewServeMux()
	routes := map[string]struct {
		route Dataset
		path  string
		name  string
	}{
		EventsRoute:     {Events, EventsRoute, "hunt_events"},
		DetectionsRoute: {Detections, DetectionsRoute, "hunt_detections"},
	}
	for _, entry := range routes {
		handler, err := NewHandler(entry.route, HandlerOptions{Hunter: options.Hunter, MaxBodyBytes: options.MaxBodyBytes})
		if err != nil {
			return nil, err
		}
		mux.Handle(entry.path, options.Instrumentation.Handle(entry.name, handler))
	}

	return httpx.NewServer(httpx.ServerOptions{
		Name:              "query",
		Address:           options.Address,
		Handler:           mux,
		TLS:               options.TLS,
		Logger:            options.Logger,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       options.ReadTimeout,
		WriteTimeout:      options.WriteTimeout,
		IdleTimeout:       options.IdleTimeout,
		ShutdownTimeout:   options.ShutdownTimeout,
		MaxHeaderBytes:    16 << 10,
	})
}
