package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/hunt"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := queryAPI(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "query-api: %v\n", err)
		os.Exit(1)
	}
}

// The read plane. It holds the only read connection to the analytical store, it
// consumes no topic and it changes nothing: an expensive question asked here
// cannot slow the pipeline that is still admitting telemetry, and cannot reach
// the surface an operator uses to act on what it finds.
func queryAPI(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	store, err := clickhouse.NewHunter(settings.store)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// Migrations are applied by store-migrator, never here. This only refuses to
	// answer from a store behind the schema it ships, because a missing column is
	// a question answered wrongly rather than not at all.
	schemaCtx, cancel := context.WithTimeout(ctx, settings.store.Timeout)
	defer cancel()
	if err := store.VerifySchema(schemaCtx); err != nil {
		return err
	}

	key, err := cursorKey(settings)
	if err != nil {
		return err
	}
	compiler, err := hunt.NewCompiler(hunt.CompilerOptions{Limits: settings.limits, CursorKey: key})
	if err != nil {
		return err
	}

	hunter, err := hunt.NewHunter(hunt.HunterOptions{
		Source:   store,
		Compiler: compiler,
		Metrics:  hunt.NewMetrics(platform.Metrics()),
		Logger:   platform.Logger(),
	})
	if err != nil {
		return err
	}

	transport, err := mutualTransport(settings)
	if err != nil {
		return err
	}

	listener, err := hunt.NewServer(hunt.ServerOptions{
		Address:         settings.address,
		TLS:             transport,
		Hunter:          hunter,
		Instrumentation: platform.HTTP(),
		Logger:          platform.Logger(),
		MaxBodyBytes:    settings.maxBodyBytes,
		ReadTimeout:     settings.readTimeout,
		WriteTimeout:    settings.writeTimeout,
		IdleTimeout:     settings.idleTimeout,
		ShutdownTimeout: platform.ShutdownTimeout(),
	})
	if err != nil {
		return err
	}

	platform.Health().Register("store", store.Ping)
	platform.Add(listener)

	platform.Logger().Info("query_api_configured",
		slog.String("address", listener.Address()),
		slog.String("store_database", settings.store.Database),
		slog.Duration("window", settings.limits.Window),
		slog.Int("page", settings.limits.Page),
		slog.Int("page_max", settings.limits.MaxPage),
		slog.Duration("read_budget", settings.limits.Timeout),
		slog.Bool("cursor_key_configured", !settings.cursorKey.Empty()),
	)

	return platform.Run(ctx)
}

// The scope a query is answered within comes from the caller's certificate, so
// this listener has no plaintext mode and no mode without a client certificate
// authority: without one there is nobody to be authorised as.
func mutualTransport(settings configuration) (*tls.Config, error) {
	material, err := tlsx.NewMaterial(settings.certificateFile, settings.keyFile, settings.callerCAFile)
	if err != nil {
		return nil, err
	}
	return material.MutualServerConfig()
}

// A key nobody configured is generated here and lives as long as the process, so
// the cursors it issued stop being spendable when it stops running. More than
// one replica behind one address has to be given the same key or a page will
// resume on whichever replica issued it and nowhere else.
func cursorKey(settings configuration) ([]byte, error) {
	if settings.cursorKey.Empty() {
		return hunt.RandomCursorKey()
	}
	return []byte(settings.cursorKey.Reveal()), nil
}
