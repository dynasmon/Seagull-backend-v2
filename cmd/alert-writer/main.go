package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/dynasmon/Seagull-backend-v2/internal/alert"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertfile"
	"github.com/dynasmon/Seagull-backend-v2/internal/alertstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := writer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "alert-writer: %v\n", err)
		os.Exit(1)
	}
}

// The consumer that puts a detection in front of a person. It reads what the
// analysis engine decided, exactly as the detection writer does, and the two
// never meet: one materialises an analytical record and the other opens a piece
// of work, and either can fail without stopping the other.
func writer(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	floor, err := alert.ParseFloor(settings.floor)
	if err != nil {
		return err
	}

	tuning, err := alerting(settings.tuning)
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	store, err := postgres.New(ctx, settings.store)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Migrations are applied by alert-migrator, never here. This only refuses to
	// run against a store behind the schema it ships.
	schemaCtx, cancel := context.WithTimeout(ctx, settings.store.Timeout)
	defer cancel()
	if err := store.VerifySchema(schemaCtx); err != nil {
		return err
	}

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      settings.brokers,
		Topic:        settings.topology.Detections.Name,
		Group:        settings.group,
		ClientID:     serviceName,
		MaxRecords:   settings.batchDetections,
		FetchMaxWait: settings.fetchMaxWait,
		Metrics:      broker.NewConsumerMetrics(platform.Metrics()),
		Security:     settings.security,
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	topologyCtx, cancelTopology := context.WithTimeout(ctx, settings.store.Timeout)
	defer cancelTopology()
	drift, err := consumer.VerifyTopics(topologyCtx, settings.topology.Detections)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	component, err := alertstore.NewWriter(alertstore.WriterOptions{
		Source:        source{consumer: consumer},
		Sink:          store,
		Stories:       store.Incidents(),
		Tuning:        tuning,
		Floor:         floor,
		Metrics:       alertstore.NewMetrics(platform.Metrics()),
		Logger:        platform.Logger(),
		WriteTimeout:  settings.store.Timeout,
		RetryDelay:    settings.retryDelay,
		MaxRetryDelay: settings.maxRetryDelay,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("alert-store", store.Ping)
	platform.Health().Register("backbone", consumer.Ping)
	platform.Add(component)

	platform.Logger().Info("alert_writer_configured",
		slog.String("topic", settings.topology.Detections.Name),
		slog.String("group", settings.group),
		slog.Int("batch_detections", settings.batchDetections),
		slog.String("severity_floor", settings.floor),
		slog.String("alerting_document", settings.tuning),
		slog.String("tuning", tuning.ID()),
		slog.Int("folds", tuning.Rules()),
		slog.Int("suppressions", tuning.Suppressions()),
		slog.String("store_database", settings.store.Database),
	)

	return platform.Run(ctx)
}

// A document nobody declared is the built-in fold: alerts still fold per rule
// and per agent, and nothing is silenced after being closed.
func alerting(path string) (*alert.Tuning, error) {
	if path == "" {
		return alert.NewTuning(alertfile.Defaults, nil, nil)
	}
	directory, name := filepath.Split(path)
	if directory == "" {
		directory = "."
	}
	return alertfile.Tuning(os.DirFS(directory), name)
}
