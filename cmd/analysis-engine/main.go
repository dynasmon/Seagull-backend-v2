package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := engine(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "analysis-engine: %v\n", err)
		os.Exit(1)
	}
}

func engine(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      settings.brokers,
		Topic:        settings.topology.Events.Name,
		Group:        settings.group,
		ClientID:     serviceName,
		MaxRecords:   settings.batchEvents,
		FetchMaxWait: settings.fetchMaxWait,
		Metrics:      broker.NewConsumerMetrics(platform.Metrics()),
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	// The topology is applied by backbone-migrator, never here. This only refuses
	// to consume when the topic it reads is missing or reshaped.
	topologyCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()
	drift, err := consumer.VerifyTopics(topologyCtx, settings.topology.Events)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	component, err := analysis.NewEngine(analysis.EngineOptions{
		Source:  source{consumer: consumer},
		Metrics: analysis.NewMetrics(platform.Metrics()),
		Logger:  platform.Logger(),
	})
	if err != nil {
		return err
	}

	platform.Health().Register("backbone", consumer.Ping)
	platform.Add(component)

	platform.Logger().Info("analysis_engine_configured",
		slog.String("topic", settings.topology.Events.Name),
		slog.String("group", settings.group),
		slog.Int("batch_events", settings.batchEvents),
	)

	return platform.Run(ctx)
}
