package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := migrate(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "store-migrator: %v\n", err)
		os.Exit(1)
	}
}

func migrate(ctx context.Context) error {
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

	migrator, err := clickhouse.NewMigrator(settings.store)
	if err != nil {
		return err
	}
	defer func() { _ = migrator.Close() }()

	// No deadline: a migration takes as long as it takes, and a signal still stops
	// it. Partial progress is reported even when the run fails.
	applied, err := migrator.Apply(ctx)
	for _, name := range applied {
		logger.Info("migration_applied", slog.String("migration", name))
	}
	if err != nil {
		return err
	}

	logger.Info("store_schema_current",
		slog.String("database", settings.store.Database),
		slog.Int("applied", len(applied)),
	)
	return nil
}
