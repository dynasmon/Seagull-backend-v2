package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/health"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ops"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
)

type Config struct {
	Name             string
	LogLevel         string
	LogFormat        string
	OpsAddress       string
	ShutdownTimeout  time.Duration
	ReadinessCache   time.Duration
	ReadinessTimeout time.Duration
}

// The operational surface listens on loopback unless a deployment says
// otherwise, so metrics and readiness are never published by accident.
func LoadConfig(name string, parser *config.Parser) Config {
	return Config{
		Name:             name,
		LogLevel:         parser.Enum("SEAGULL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:        parser.Enum("SEAGULL_LOG_FORMAT", log.FormatJSON, log.FormatJSON, log.FormatText),
		OpsAddress:       parser.String("SEAGULL_OPS_ADDRESS", "127.0.0.1:9100"),
		ShutdownTimeout:  parser.Duration("SEAGULL_SHUTDOWN_TIMEOUT", 20*time.Second, time.Second, 5*time.Minute),
		ReadinessCache:   parser.Duration("SEAGULL_READINESS_CACHE", 5*time.Second, 0, time.Minute),
		ReadinessTimeout: parser.Duration("SEAGULL_READINESS_TIMEOUT", 2*time.Second, 100*time.Millisecond, 30*time.Second),
	}
}

type Service struct {
	config          Config
	logger          *slog.Logger
	metrics         *metrics.Registry
	health          *health.Registry
	instrumentation *httpx.Instrumentation
	group           *run.Group
	operational     *httpx.Server
}

func New(configuration Config) (*Service, error) {
	if configuration.Name == "" {
		return nil, errors.New("a service needs a name")
	}

	build := buildinfo.Read()
	logger, err := log.New(os.Stdout, log.Options{
		Level:   configuration.LogLevel,
		Format:  configuration.LogFormat,
		Service: configuration.Name,
		Version: build.Version,
	})
	if err != nil {
		return nil, err
	}

	registry := metrics.New(configuration.Name)
	checks := health.New(configuration.ReadinessCache, configuration.ReadinessTimeout)
	instrumentation := httpx.NewInstrumentation(registry)

	operational, err := ops.NewServer(ops.Options{
		Service:         configuration.Name,
		Address:         configuration.OpsAddress,
		Health:          checks,
		Metrics:         registry,
		Instrumentation: instrumentation,
		Logger:          logger,
		ShutdownTimeout: configuration.ShutdownTimeout,
	})
	if err != nil {
		return nil, err
	}

	group := run.NewGroup(logger, configuration.ShutdownTimeout)
	group.Add(operational)

	logger.Info("service_configured",
		slog.String("revision", build.Revision),
		slog.Bool("modified", build.Modified),
		slog.String("ops_address", operational.Address()),
	)

	return &Service{
		config:          configuration,
		logger:          logger,
		metrics:         registry,
		health:          checks,
		instrumentation: instrumentation,
		group:           group,
		operational:     operational,
	}, nil
}

func (s *Service) Logger() *slog.Logger { return s.logger }

func (s *Service) Metrics() *metrics.Registry { return s.metrics }

func (s *Service) Health() *health.Registry { return s.health }

// Every listener in a process shares one set of HTTP instruments; the route
// label is what separates them.
func (s *Service) HTTP() *httpx.Instrumentation { return s.instrumentation }

func (s *Service) ShutdownTimeout() time.Duration { return s.config.ShutdownTimeout }

func (s *Service) OperationalAddress() string { return s.operational.Address() }

func (s *Service) Add(members ...run.Runnable) { s.group.Add(members...) }

func (s *Service) Run(ctx context.Context) error {
	drainCtx, stopDraining := context.WithCancel(ctx)
	defer stopDraining()

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-drainCtx.Done()
		s.health.Drain()
	}()

	err := s.group.Run(log.Into(ctx, s.logger))
	stopDraining()
	<-drained

	if err != nil {
		return fmt.Errorf("%s: %w", s.config.Name, err)
	}
	return nil
}
