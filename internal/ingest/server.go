package ingest

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-v2/internal/platform/httpx"
)

type ServerOptions struct {
	Address         string
	TLS             *tls.Config
	Handler         *Handler
	Instrumentation *httpx.Instrumentation
	Logger          *slog.Logger
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

func NewServer(options ServerOptions) (*httpx.Server, error) {
	if options.Handler == nil {
		return nil, errors.New("the ingest listener needs a handler")
	}
	if options.Instrumentation == nil {
		return nil, errors.New("the ingest listener shares the process http instrumentation")
	}

	mux := http.NewServeMux()
	mux.Handle(EventsRoute, options.Instrumentation.Handle("ingest_events", options.Handler))

	return httpx.NewServer(httpx.ServerOptions{
		Name:              "ingest",
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
