package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-v2/internal/platform/httpx"
	"github.com/dynasmon/Seagull-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-v2/internal/platform/tlsx"
	"github.com/dynasmon/Seagull-v2/internal/protocol"
)

const contentType = "application/x-protobuf"

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := controlAPI(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "control-api: %v\n", err)
		os.Exit(1)
	}
}

func controlAPI(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	transport, err := transportConfig(settings)
	if err != nil {
		return err
	}

	listener, err := httpx.NewServer(httpx.ServerOptions{
		Name:              "control-api",
		Address:           settings.address,
		Handler:           routes(platform.HTTP(), time.Now),
		TLS:               transport,
		Logger:            platform.Logger(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       settings.readTimeout,
		WriteTimeout:      settings.writeTimeout,
		IdleTimeout:       settings.idleTimeout,
		ShutdownTimeout:   platform.ShutdownTimeout(),
		MaxHeaderBytes:    16 << 10,
	})
	if err != nil {
		return err
	}

	platform.Logger().Info("control_api_configured",
		slog.Bool("tls", transport != nil),
		slog.String("address", listener.Address()),
	)
	platform.Add(listener)

	return platform.Run(ctx)
}

func transportConfig(settings configuration) (*tls.Config, error) {
	if settings.certificateFile == "" {
		return nil, nil
	}
	material, err := tlsx.NewMaterial(settings.certificateFile, settings.keyFile, "")
	if err != nil {
		return nil, err
	}
	return material.ServerConfig(), nil
}

func routes(instrumentation *httpx.Instrumentation, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/descriptor", instrumentation.Handle("descriptor", descriptorHandler(now)))
	return mux
}

func descriptorHandler(now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		encoded, err := proto.Marshal(protocol.Descriptor(now()))
		if err != nil {
			http.Error(w, "response encoding failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(encoded)
	})
}
