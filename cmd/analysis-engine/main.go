package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/analysis"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
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

	// What the engine decides leaves the process on a topic of its own, produced
	// by a client of its own: the group that reads telemetry and the producer
	// that reports findings fail apart from each other.
	detections, err := broker.NewDetections(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Detections.Name,
		ClientID: serviceName,
	})
	if err != nil {
		return err
	}
	defer detections.Close()

	engineRuntime := runtime{
		bounds:       settings.state,
		partitioning: detectionstate.Partitioning{By: broker.PartitionedBy, Sole: settings.sole},
		skew:         settings.skew,
	}

	// A process that cannot read its rules does not start: running against a
	// ruleset nobody chose is worse than refusing to run.
	registry, err := ruleset.New(ruleset.Options{
		Source:  written(settings.rules),
		Metrics: ruleset.NewMetrics(platform.Metrics()),
		Logger:  platform.Logger(),
	})
	if err != nil {
		return err
	}

	// The rule tree this process ships with is what it runs until the control
	// plane has published something: an engine that cannot reach a control plane
	// still detects, and a published ruleset takes over the moment it is read.
	published, err := publishedRulesets(ctx, settings, platform, registry, engineRuntime)
	if err != nil {
		return err
	}
	defer published.reader.Close()

	keeper, err := keeping(engineRuntime, registry.Current())
	if err != nil {
		return err
	}
	analysis.ObserveState(platform.Metrics(), settings.state, keeper.Keys)

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      settings.brokers,
		Topic:        settings.topology.Events.Name,
		Group:        settings.group,
		ClientID:     serviceName,
		MaxRecords:   settings.batchEvents,
		FetchMaxWait: settings.fetchMaxWait,
		Metrics:      broker.NewConsumerMetrics(platform.Metrics()),
		Recovery:     recovering(engineRuntime, settings.topology.Events.Partitions, registry, platform.Logger()),
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	// The topology is applied by backbone-migrator, never here. This only refuses
	// to consume when the topic it reads is missing or reshaped.
	topologyCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()
	drift, err := consumer.VerifyTopics(topologyCtx, settings.topology.Events, settings.topology.Detections)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	component, err := analysis.NewEngine(analysis.EngineOptions{
		Source:         source{consumer: consumer},
		Rules:          rules{registry: registry},
		State:          keeper,
		Detections:     detections,
		Metrics:        analysis.NewMetrics(platform.Metrics()),
		Logger:         platform.Logger(),
		PublishTimeout: settings.publishTimeout,
		RetryDelay:     settings.retryDelay,
		MaxRetryDelay:  settings.maxRetryDelay,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("backbone", consumer.Ping)
	platform.Health().Register("detections", detections.Ping)
	platform.Add(published.follower(platform.Logger(), registry, engineRuntime))
	platform.Add(component)

	platform.Logger().Info("analysis_engine_configured",
		slog.String("topic", settings.topology.Events.Name),
		slog.String("detections_topic", settings.topology.Detections.Name),
		slog.String("group", settings.group),
		slog.String("rules", settings.rules),
		slog.String("rulesets_topic", settings.topology.Rulesets.Name),
		slog.String("ruleset", string(registry.Current().ID())),
		slog.Int("batch_events", settings.batchEvents),
		slog.Duration("state_window", settings.state.Window),
		slog.Int("state_observations_per_key", settings.state.ObservationsPerKey),
		slog.Int("state_keys", settings.state.Keys),
		slog.Any("stream_keyed_by", broker.PartitionedBy),
		slog.Bool("sole_reader", settings.sole),
		slog.Duration("state_recovery", engineRuntime.recovering(registry.Current())),
	)

	return platform.Run(ctx)
}
