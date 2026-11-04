package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/ingest"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := gateway(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ingest-gateway: %v\n", err)
		os.Exit(1)
	}
}

func gateway(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	material, err := tlsx.NewMaterial(settings.certificateFile, settings.keyFile, settings.agentCAFile)
	if err != nil {
		return err
	}
	mutual, err := material.MutualServerConfig()
	if err != nil {
		return err
	}

	publisher, err := broker.NewPublisher(broker.Config{
		Brokers:         settings.brokers,
		Topic:           settings.topology.Events.Name,
		MaxMessageBytes: settings.topology.Events.MaxMessageBytes,
		ClientID:        settings.admissionRules.Gateway,
		Security:        settings.security,
	})
	if err != nil {
		return err
	}
	defer publisher.Close()

	assets, err := broker.NewInventory(broker.Config{
		Brokers:         settings.brokers,
		Topic:           settings.topology.Inventory.Name,
		MaxMessageBytes: settings.topology.Inventory.MaxMessageBytes,
		ClientID:        settings.inventoryRules.Gateway,
		Security:        settings.security,
	})
	if err != nil {
		return err
	}
	defer assets.Close()

	reports, err := broker.NewStatus(broker.Config{
		Brokers:         settings.brokers,
		Topic:           settings.topology.Status.Name,
		MaxMessageBytes: settings.topology.Status.MaxMessageBytes,
		ClientID:        settings.statusRules.Gateway,
		Security:        settings.security,
	})
	if err != nil {
		return err
	}
	defer reports.Close()

	findings, err := broker.NewAssessments(broker.Config{
		Brokers:         settings.brokers,
		Topic:           settings.topology.Assessments.Name,
		MaxMessageBytes: settings.topology.Assessments.MaxMessageBytes,
		ClientID:        settings.assessments.Gateway,
		Security:        settings.security,
	})
	if err != nil {
		return err
	}
	defer findings.Close()

	// The topology is applied by backbone-migrator, never here. This only refuses
	// to serve agents when a topic it would publish to is missing or reshaped.
	topologyCtx, cancel := context.WithTimeout(ctx, settings.publishTimeout)
	defer cancel()
	drift, err := publisher.VerifyTopics(topologyCtx,
		settings.topology.Events, settings.topology.Inventory, settings.topology.Status, settings.topology.Assessments)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}
	broker.LogDurability(ctx, platform.Logger(),
		settings.topology.Events, settings.topology.Inventory, settings.topology.Status, settings.topology.Assessments)
	broker.ObserveDurability(platform.Metrics(),
		settings.topology.Events, settings.topology.Inventory, settings.topology.Status, settings.topology.Assessments)

	admitted, err := admissible(ctx, settings, platform)
	if err != nil {
		return err
	}
	defer admitted.close()

	served, err := routes(settings, sinks{events: publisher, inventory: assets, status: reports, assessments: findings},
		admitted.held, platform.Metrics(), platform.Logger())
	if err != nil {
		return err
	}
	served.Address = settings.address
	served.TLS = mutual
	served.Instrumentation = platform.HTTP()
	served.Logger = platform.Logger()
	served.ReadTimeout = settings.readTimeout
	served.WriteTimeout = settings.writeTimeout
	served.IdleTimeout = settings.idleTimeout
	served.ShutdownTimeout = platform.ShutdownTimeout()
	listener, err := ingest.NewServer(served)
	if err != nil {
		return err
	}

	platform.Logger().Info("agent_roster_read",
		slog.String("agents_topic", settings.topology.Agents.Name),
		slog.Int("agents_known", admitted.held.Known()),
		slog.Int("agents_refused", admitted.held.Refused()),
	)

	platform.Health().Register("backbone", publisher.Ping)
	platform.Health().Register("inventory-backbone", assets.Ping)
	platform.Health().Register("status-backbone", reports.Ping)
	platform.Health().Register("assessment-backbone", findings.Ping)
	platform.Add(admitted.follower(platform.Logger()))
	platform.Add(listener)

	return platform.Run(ctx)
}
