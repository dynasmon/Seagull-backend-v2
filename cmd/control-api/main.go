package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
)

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

	instruments := control.NewMetrics(platform.Metrics())

	registry, err := control.NewRegistry(control.RegistryOptions{
		Source:  policySource(settings.policyFile),
		Metrics: instruments,
		Logger:  platform.Logger(),
	})
	if err != nil {
		return err
	}

	key, err := sessionKey(settings)
	if err != nil {
		return err
	}
	issuer, err := authz.NewIssuer(key, settings.sessionLife)
	if err != nil {
		return err
	}
	sessions, err := control.NewSessions(control.SessionOptions{
		Issuer:     issuer,
		PerSubject: settings.sessionsPer,
		Capacity:   settings.sessionsTotal,
	})
	if err != nil {
		return err
	}

	guard, err := control.NewGuard(control.GuardOptions{
		Sessions: sessions,
		Registry: registry,
		Limiter:  ratelimit.NewLimiter(settings.ratePerSecond, settings.rateBurst, settings.trackedCallers),
		Metrics:  instruments,
		Logger:   platform.Logger(),
	})
	if err != nil {
		return err
	}

	transport, err := mutualTransport(settings)
	if err != nil {
		return err
	}

	listener, err := control.NewServer(control.ServerOptions{
		Address:         settings.address,
		TLS:             transport,
		Guard:           guard,
		Sessions:        sessions,
		Registry:        registry,
		Metrics:         instruments,
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

	policy := registry.Current()
	platform.Logger().Info("control_api_configured",
		slog.String("address", listener.Address()),
		slog.String("policy", policy.ID().String()),
		slog.Int("roles", policy.Roles()),
		slog.Int("bindings", policy.Bindings()),
		slog.Duration("session_lifetime", settings.sessionLife),
		slog.Bool("session_key_configured", !settings.sessionKey.Empty()),
	)

	platform.Add(listener)
	platform.Add(sweeper{sessions: sessions, every: settings.sessionLife})

	return platform.Run(ctx)
}

// The caller is authenticated by certificate, so this listener has no plaintext
// mode and no mode without a client certificate authority: without one there is
// nobody to be authorised as.
func mutualTransport(settings configuration) (*tls.Config, error) {
	material, err := tlsx.NewMaterial(settings.certificateFile, settings.keyFile, settings.callerCAFile)
	if err != nil {
		return nil, err
	}
	return material.MutualServerConfig()
}

func policySource(path string) control.Source {
	directory, name := filepath.Split(path)
	if directory == "" {
		directory = "."
	}
	return control.SourceFunc(func() (*authz.Policy, error) {
		return policyfile.Policy(os.DirFS(directory), name)
	})
}

// A key nobody configured is a key nobody shares: the sessions this process
// issues stop being spendable when it stops running.
func sessionKey(settings configuration) ([]byte, error) {
	if settings.sessionKey.Empty() {
		return authz.RandomSessionKey()
	}
	return []byte(settings.sessionKey.Reveal()), nil
}

type sweeper struct {
	sessions *control.Sessions
	every    time.Duration
}

func (s sweeper) Name() string { return "session-sweeper" }

func (s sweeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.sessions.Sweep(time.Now())
		}
	}
}
