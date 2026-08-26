package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := provision(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "backbone-migrator: %v\n", err)
		os.Exit(1)
	}
}

func provision(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	logger, err := log.New(os.Stdout, log.Options{
		Level:   settings.logLevel,
		Format:  settings.logFormat,
		Service: serviceName,
		Version: buildinfo.Read().Version,
	})
	if err != nil {
		return err
	}

	provisioner, err := broker.NewProvisioner(settings.brokers, serviceName)
	if err != nil {
		return err
	}
	defer provisioner.Close()

	// No deadline: a signal still stops it, and partial progress is reported even
	// when the run fails.
	changed, err := provisioner.Apply(ctx, settings.topology.Topics())
	for _, change := range changed {
		logger.Info("backbone_topology_changed", slog.String("change", change))
	}
	if err != nil {
		return err
	}

	logger.Info("backbone_topology_current",
		slog.String("events_topic", settings.topology.Events.Name),
		slog.String("quarantine_topic", settings.topology.Quarantine.Name),
		slog.String("detections_topic", settings.topology.Detections.Name),
		slog.Int("changes", len(changed)),
	)
	return nil
}
