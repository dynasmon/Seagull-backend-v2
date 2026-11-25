package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfindingstore"
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
		fmt.Fprintf(os.Stderr, "agent-finding-writer: %v\n", err)
		os.Exit(1)
	}
}

// The consumer that keeps what the platform found about its agents. It has a
// failure domain of its own: a store outage costs how current the findings an
// operator reads are, and never a decision about an agent or anything an agent
// sends.
func writer(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}
	denials := broker.NewDenials(platform.Metrics())
	settings.security = settings.security.Observed(denials)
	platform.Health().Register("backbone-access", denials.Check)

	store, err := clickhouse.NewAgentFindingStore(settings.store)
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
		Topic:        settings.topology.AgentFindings.Name,
		Group:        serviceName,
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
	drift, err := consumer.VerifyTopics(topologyCtx, settings.topology.AgentFindings, settings.topology.AgentFindingsQuarantine)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}
	broker.LogDurability(ctx, platform.Logger(), settings.topology.AgentFindings, settings.topology.AgentFindingsQuarantine)
	broker.ObserveDurability(platform.Metrics(), settings.topology.AgentFindings, settings.topology.AgentFindingsQuarantine)

	refused, err := broker.NewQuarantine(broker.Config{
		Brokers:         settings.brokers,
		Topic:           settings.topology.AgentFindingsQuarantine.Name,
		MaxMessageBytes: settings.topology.AgentFindingsQuarantine.MaxMessageBytes,
		ClientID:        serviceName,
		Security:        settings.security,
	})
	if err != nil {
		return err
	}
	defer refused.Close()

	component, err := agentfindingstore.NewWriter(agentfindingstore.WriterOptions{
		Source:        source{consumer: consumer},
		Sink:          store,
		Quarantine:    quarantine{topic: refused},
		Metrics:       agentfindingstore.NewMetrics(platform.Metrics()),
		Logger:        platform.Logger(),
		WriteTimeout:  settings.store.Timeout,
		RetryDelay:    settings.retryDelay,
		MaxRetryDelay: settings.maxRetryDelay,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("agent-finding-store", store.Ping)
	platform.Health().Register("backbone", consumer.Ping)
	platform.Add(component)

	platform.Logger().Info("agent_finding_writer_configured",
		slog.String("topic", settings.topology.AgentFindings.Name),
		slog.String("quarantine_topic", settings.topology.AgentFindingsQuarantine.Name),
		slog.String("group", serviceName),
		slog.Int("batch_records", settings.batchRecords),
		slog.String("store_database", settings.store.Database),
	)

	return platform.Run(ctx)
}
