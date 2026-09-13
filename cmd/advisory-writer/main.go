package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := writer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "advisory-writer: %v\n", err)
		os.Exit(1)
	}
}

// The consumer that keeps every version of every advisory the platform has
// read. It is not the importer, so the one process that talks to the internet
// holds no store credential, and a store that cannot be reached holds up
// neither the feeds nor anything else.
func writer(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	store, err := clickhouse.NewAdvisoryStore(settings.store)
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
		Topic:        settings.topology.Advisories.Name,
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
	drift, err := consumer.VerifyTopics(topologyCtx, settings.topology.Advisories, settings.topology.AdvisoriesQuarantine)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	refused, err := broker.NewQuarantine(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.AdvisoriesQuarantine.Name,
		ClientID: serviceName,
		Security: settings.security,
	})
	if err != nil {
		return err
	}
	defer refused.Close()

	component, err := advisorystore.NewWriter(advisorystore.WriterOptions{
		Source:        source{consumer: consumer},
		Sink:          store,
		Quarantine:    quarantine{topic: refused},
		Metrics:       advisorystore.NewMetrics(platform.Metrics()),
		Logger:        platform.Logger(),
		WriteTimeout:  settings.store.Timeout,
		RetryDelay:    settings.retryDelay,
		MaxRetryDelay: settings.maxRetryDelay,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("advisory-store", store.Ping)
	platform.Health().Register("backbone", consumer.Ping)
	platform.Add(component)

	platform.Logger().Info("advisory_writer_configured",
		slog.String("topic", settings.topology.Advisories.Name),
		slog.String("quarantine_topic", settings.topology.AdvisoriesQuarantine.Name),
		slog.String("group", settings.group),
		slog.Int("batch_records", settings.batchRecords),
		slog.String("store_database", settings.store.Database),
	)

	return platform.Run(ctx)
}
