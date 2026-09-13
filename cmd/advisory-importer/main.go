package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisoryfeed"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/osv"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/buildinfo"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := importer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "advisory-importer: %v\n", err)
		os.Exit(1)
	}
}

// The one process that reads the internet. It holds no store and names no
// asset: what a feed says reaches the platform as a validated advisory on the
// backbone, and a feed that fails or lies can stop nothing but this.
func importer(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	publisher, err := broker.NewAdvisories(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Advisories.Name,
		ClientID: serviceName,
		Security: settings.security,
	})
	if err != nil {
		return err
	}
	defer publisher.Close()

	// The topology is applied by backbone-migrator, never here. This only refuses
	// to publish to a topic that is missing or reshaped.
	topologyCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()
	drift, err := publisher.VerifyTopics(topologyCtx, settings.topology.Advisories)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	backlog, err := broker.NewStateLog(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Advisories.Name,
		ClientID: serviceName,
		Security: settings.security,
	}, settings.replayRecords)
	if err != nil {
		return err
	}
	defer backlog.Close()

	fetcher, err := client(settings)
	if err != nil {
		return err
	}
	export, err := osv.NewExport(osv.ExportOptions{
		Base:           settings.export,
		Client:         fetcher,
		MaxIndexBytes:  settings.maxIndexBytes,
		MaxRecordBytes: settings.maxRecordBytes,
		UserAgent:      serviceName + "/" + buildinfo.Read().Version,
	})
	if err != nil {
		return err
	}

	component, err := advisoryfeed.NewImporter(advisoryfeed.Options{
		Source:        osv.Source,
		Feeds:         settings.feeds,
		Origin:        export,
		Translate:     osv.Translate,
		Normalization: osv.Normalization,
		Log:           publisher,
		History:       history{log: backlog, logger: platform.Logger()},
		Metrics:       advisoryfeed.NewMetrics(platform.Metrics()),
		Logger:        platform.Logger(),
		Interval:      settings.interval,
		RetryDelay:    settings.retryDelay,
		Backoff:       settings.backoff,
		Attempts:      settings.attempts,
		Concurrency:   settings.concurrency,
		Batch:         settings.batch,
		Now:           time.Now,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("backbone", publisher.Ping)
	platform.Add(component)

	platform.Logger().Info("advisory_importer_configured",
		slog.String("topic", settings.topology.Advisories.Name),
		slog.String("export", settings.export),
		slog.String("feeds", strings.Join(settings.feeds, ",")),
		slog.Duration("interval", settings.interval),
		slog.Int("concurrency", settings.concurrency),
	)

	return platform.Run(ctx)
}
