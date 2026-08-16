package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
)

type ServerOptions struct {
	Name              string
	Address           string
	Handler           http.Handler
	TLS               *tls.Config
	Logger            *slog.Logger
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
}

type Server struct {
	name            string
	listener        net.Listener
	server          *http.Server
	secure          bool
	shutdownTimeout time.Duration
	logger          *slog.Logger
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.Name == "" {
		return nil, errors.New("a server needs a name")
	}
	if options.Handler == nil {
		return nil, fmt.Errorf("%s: a server needs a handler", options.Name)
	}
	if options.Logger == nil {
		return nil, fmt.Errorf("%s: a server needs a logger", options.Name)
	}

	listener, err := net.Listen("tcp", options.Address)
	if err != nil {
		return nil, fmt.Errorf("%s: listen on %q: %w", options.Name, options.Address, err)
	}

	server := &http.Server{
		Handler:           options.Handler,
		TLSConfig:         options.TLS,
		ReadHeaderTimeout: options.ReadHeaderTimeout,
		ReadTimeout:       options.ReadTimeout,
		WriteTimeout:      options.WriteTimeout,
		IdleTimeout:       options.IdleTimeout,
		MaxHeaderBytes:    options.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(options.Logger.Handler(), slog.LevelWarn),
	}

	return &Server{
		name:            options.Name,
		listener:        listener,
		server:          server,
		secure:          options.TLS != nil,
		shutdownTimeout: options.ShutdownTimeout,
		logger:          options.Logger,
	}, nil
}

func (s *Server) Name() string { return s.name }

func (s *Server) Address() string { return s.listener.Addr().String() }

func (s *Server) Run(ctx context.Context) error {
	s.logger.Info("listener_ready",
		slog.String("listener", s.name),
		slog.String("address", s.Address()),
		slog.Bool("tls", s.secure),
	)

	// Requests inherit the listener's logger but not its cancellation: a
	// shutdown drains what is in flight, and cancelling it here would abandon
	// work the caller was told to wait for.
	base := log.Into(context.WithoutCancel(ctx), s.logger)
	s.server.BaseContext = func(net.Listener) context.Context { return base }

	serving := make(chan error, 1)
	go func() {
		if s.secure {
			serving <- s.server.ServeTLS(s.listener, "", "")
			return
		}
		serving <- s.server.Serve(s.listener)
	}()

	select {
	case err := <-serving:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		_ = s.server.Close()
		<-serving
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	<-serving
	return nil
}
