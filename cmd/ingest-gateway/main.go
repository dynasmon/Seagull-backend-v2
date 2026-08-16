package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dynasmon/Seagull-v2/internal/broker"
	"github.com/dynasmon/Seagull-v2/internal/ingest"
	"github.com/dynasmon/Seagull-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-v2/internal/platform/tlsx"
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
		Brokers:  settings.brokers,
		Topic:    settings.topic,
		ClientID: settings.admissionRules.Gateway,
	})
	if err != nil {
		return err
	}
	defer publisher.Close()

	admitter, err := ingest.NewAdmitter(publisher, settings.admissionRules, ingest.NewMetrics(platform.Metrics()))
	if err != nil {
		return err
	}

	handler, err := ingest.NewHandler(ingest.HandlerOptions{
		Admitter:       admitter,
		Limiter:        ingest.NewLimiter(settings.ratePerSecond, settings.rateBurst, settings.trackedAgents),
		MaxBodyBytes:   settings.maxBodyBytes,
		PublishTimeout: settings.publishTimeout,
	})
	if err != nil {
		return err
	}

	listener, err := ingest.NewServer(ingest.ServerOptions{
		Address:         settings.address,
		TLS:             mutual,
		Handler:         handler,
		Instrumentation: platform.HTTP(),
		Logger:          platform.Logger(),
		ReadTimeout:     settings.readTimeout,
		WriteTimeout:    settings.writeTimeout,
		IdleTimeout:     settings.idleTimeout,
		ShutdownTimeout: platform.ShutdownTimeout(),
	})
	if err != nil {
		return err
	}

	platform.Health().Register("backbone", publisher.Ping)
	platform.Add(listener)

	return platform.Run(ctx)
}
