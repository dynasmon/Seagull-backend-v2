package ingest

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
	Handler         *Handler
	Inventory       *Handler
	Status          *Handler
	Assessments     *Handler
	Instrumentation *httpx.Instrumentation
	Logger          *slog.Logger
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

func NewServer(options ServerOptions) (*httpx.Server, error) {
	routed, err := Routes(options)
	if err != nil {
		return nil, err
	}

	return httpx.NewServer(httpx.ServerOptions{
		Name:              "ingest",
		Address:           options.Address,
		Handler:           routed,
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

// Every stream is routed where its own description says it is sent, and the
// descriptor is built from the same handlers, so the listener cannot describe a
// stream it does not route or route one it does not describe.
func Routes(options ServerOptions) (http.Handler, error) {
	if options.Handler == nil {
		return nil, errors.New("the ingest listener needs a handler")
	}
	if options.Instrumentation == nil {
		return nil, errors.New("the ingest listener shares the process http instrumentation")
	}

	mux := http.NewServeMux()
	var served []*Handler
	for _, handler := range []*Handler{options.Handler, options.Inventory, options.Status, options.Assessments} {
		if handler == nil {
			continue
		}
		mux.Handle(handler.stream.describe().GetRoute(), options.Instrumentation.Handle("ingest_"+handler.stream.name(), handler))
		served = append(served, handler)
	}
	describing, err := newDescriber(served)
	if err != nil {
		return nil, err
	}
	mux.Handle(DescriptorRoute, options.Instrumentation.Handle("ingest_descriptor", describing))
	return mux, nil
}
