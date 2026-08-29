package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/authz"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
	"github.com/dynasmon/Seagull-backend-v2/internal/ruleset"
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

	published, err := publishedRulesets(ctx, settings, platform)
	if err != nil {
		return err
	}
	defer published.close()

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
		Rulesets:        rulesets{catalogue: published.catalogue, publisher: published.publisher},
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
		slog.String("rulesets_topic", settings.topology.Rulesets.Name),
		slog.Int("rulesets_published", published.catalogue.Count()),
		slog.String("ruleset_active", published.catalogue.Activation().GetRulesetId()),
	)

	platform.Health().Register("backbone", published.publisher.Ping)
	platform.Add(published.follower(platform.Logger()))
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

// Where published rulesets live, read whole before this process answers about
// them: a control plane that has seen half the log would report an estate that
// nobody has.
type rulesetLog struct {
	catalogue *ruleset.Catalogue
	publisher *broker.Rulesets
	reader    *broker.RulesetLog
}

func publishedRulesets(ctx context.Context, settings configuration, platform *service.Service) (rulesetLog, error) {
	publisher, err := broker.NewRulesets(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Rulesets.Name,
		ClientID: serviceName,
	})
	if err != nil {
		return rulesetLog{}, err
	}

	reader, err := broker.NewRulesetLog(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Rulesets.Name,
		ClientID: serviceName,
	}, settings.logRecords)
	if err != nil {
		publisher.Close()
		return rulesetLog{}, err
	}

	held := rulesetLog{catalogue: ruleset.NewCatalogue(), publisher: publisher, reader: reader}

	startCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()

	drift, err := reader.VerifyTopics(startCtx, settings.topology.Rulesets)
	if err != nil {
		held.close()
		return rulesetLog{}, err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}
	if err := reader.Replay(startCtx, held.applying(platform.Logger())); err != nil {
		held.close()
		return rulesetLog{}, err
	}
	return held, nil
}

// A record that cannot be read is counted and stepped over rather than allowed
// to end the replay: one unreadable ruleset must not take away the ability to
// publish a good one.
func (l rulesetLog) applying(logger *slog.Logger) broker.Deliver {
	return func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			if err := l.catalogue.Read(record.Value); err != nil {
				logger.Warn("ruleset_record_refused",
					slog.Int64("offset", record.Offset),
					slog.String("key", string(record.Key)),
					slog.String("error", err.Error()),
				)
			}
		}
		return nil
	}
}

func (l rulesetLog) follower(logger *slog.Logger) follower {
	return follower{reader: l.reader, deliver: l.applying(logger)}
}

func (l rulesetLog) close() {
	if l.publisher != nil {
		l.publisher.Close()
	}
	if l.reader != nil {
		l.reader.Close()
	}
}

type follower struct {
	reader  *broker.RulesetLog
	deliver broker.Deliver
}

func (f follower) Name() string { return "ruleset-log" }

func (f follower) Run(ctx context.Context) error {
	if err := f.reader.Follow(ctx, f.deliver); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
