package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/assessmentstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := projector(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "assessment-projector: %v\n", err)
		os.Exit(1)
	}
}

// The consumer that keeps every assessment agents made of their hosts. It has
// a failure domain of its own: an assessment store outage costs how fresh a
// posture is, and never the admission or the storage of telemetry.
func projector(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	store, err := clickhouse.NewAssessmentStore(settings.store)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Migrations are applied by store-migrator, never here. This only refuses to
	// run against a store behind the schema it ships.
	schemaCtx, cancel := context.WithTimeout(ctx, settings.store.Timeout)
	defer cancel()
	if err := store.VerifySchema(schemaCtx); err != nil {
		return err
	}

	consumer, err := broker.NewConsumer(broker.ConsumerConfig{
		Brokers:      settings.brokers,
		Topic:        settings.topology.Assessments.Name,
		Group:        settings.group,
		ClientID:     serviceName,
		MaxRecords:   settings.batchRecords,
		FetchMaxWait: settings.fetchMaxWait,
		Metrics:      broker.NewConsumerMetrics(platform.Metrics()),
		Security:     settings.security,
	})
	if err != nil {
		return err
	}
	defer consumer.Close()

	// The topology is applied by backbone-migrator, never here. This only refuses
	// to consume when a topic it depends on is missing or reshaped.
	topologyCtx, cancelTopology := context.WithTimeout(ctx, settings.store.Timeout)
	defer cancelTopology()
	drift, err := consumer.VerifyTopics(topologyCtx, settings.topology.Assessments, settings.topology.AssessmentsQuarantine)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	refused, err := broker.NewQuarantine(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.AssessmentsQuarantine.Name,
		ClientID: serviceName,
		Security: settings.security,
	})
	if err != nil {
		return err
	}
	defer refused.Close()

	component, err := assessmentstore.NewProjector(assessmentstore.ProjectorOptions{
		Source:        source{consumer: consumer},
		Sink:          store,
		Quarantine:    quarantine{topic: refused},
		Metrics:       assessmentstore.NewMetrics(platform.Metrics()),
		Logger:        platform.Logger(),
		WriteTimeout:  settings.store.Timeout,
		RetryDelay:    settings.retryDelay,
		MaxRetryDelay: settings.maxRetryDelay,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("assessment-store", store.Ping)
	platform.Health().Register("backbone", consumer.Ping)
	platform.Add(component)

	platform.Logger().Info("assessment_projector_configured",
		slog.String("topic", settings.topology.Assessments.Name),
		slog.String("quarantine_topic", settings.topology.AssessmentsQuarantine.Name),
		slog.String("group", settings.group),
		slog.Int("batch_records", settings.batchRecords),
		slog.String("store_database", settings.store.Database),
	)

	return platform.Run(ctx)
}
