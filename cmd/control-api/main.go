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
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/control"
	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/ratelimit"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/tlsx"
	"github.com/dynasmon/Seagull-backend-v2/internal/policyfile"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
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

	raised, err := postgres.New(ctx, settings.alerts)
	if err != nil {
		return err
	}
	defer func() { _ = raised.Close() }()

	alertCtx, cancelAlerts := context.WithTimeout(ctx, settings.alerts.Timeout)
	defer cancelAlerts()
	if err := raised.VerifySchema(alertCtx); err != nil {
		return err
	}

	admissions, err := broker.NewAgents(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Agents.Name,
		ClientID: serviceName,
		Security: settings.security,
	})
	if err != nil {
		return err
	}
	defer admissions.Close()

	agentCtx, cancelAgents := context.WithTimeout(ctx, settings.startTimeout)
	defer cancelAgents()
	drift, err := admissions.VerifyTopics(agentCtx, settings.topology.Agents)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}

	seen, err := clickhouse.NewLiveness(settings.telemetry, settings.livenessHorizon, settings.livenessBackdating)
	if err != nil {
		return err
	}
	defer func() { _ = seen.Close() }()

	announcer, err := control.NewAnnouncer(control.AnnouncerOptions{
		Agents:     raised.Agents(),
		Admissions: admissions,
		Metrics:    instruments,
		Logger:     platform.Logger(),
		Every:      settings.announceEvery,
		Batch:      settings.announceBatch,
	})
	if err != nil {
		return err
	}

	transport, err := mutualTransport(settings)
	if err != nil {
		return err
	}

	authority, bundle, err := agentAuthority(settings)
	if err != nil {
		return err
	}

	renewalTransport, err := agentTransport(settings)
	if err != nil {
		return err
	}

	options := control.ServerOptions{
		Address:         settings.address,
		TLS:             transport,
		Guard:           guard,
		Sessions:        sessions,
		Registry:        registry,
		Rulesets:        rulesets{catalogue: published.catalogue, publisher: published.publisher},
		Alerts:          raised,
		Incidents:       raised.Incidents(),
		Agents:          raised.Agents(),
		Admissions:      admissions,
		Liveness:        seen,
		Authority:       authority,
		TrustBundle:     bundle,
		CertificateLife: settings.certificateLife,
		RenewalAddress:  settings.renewalAddress,
		RenewalTLS:      renewalTransport,
		RenewalLimiter: ratelimit.NewLimiter(
			settings.renewalsPerSecond, settings.renewalBurst, settings.trackedRenewalAgent),
		Metrics:         instruments,
		Instrumentation: platform.HTTP(),
		Logger:          platform.Logger(),
		ReadTimeout:     settings.readTimeout,
		WriteTimeout:    settings.writeTimeout,
		IdleTimeout:     settings.idleTimeout,
		ShutdownTimeout: platform.ShutdownTimeout(),
	}

	listener, err := control.NewServer(options)
	if err != nil {
		return err
	}
	renewals, err := control.NewRenewalServer(options)
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
		slog.Int("ruleset_activations", len(published.catalogue.Activations())),
		slog.String("alert_store_database", settings.alerts.Database),
		slog.String("agents_topic", settings.topology.Agents.Name),
		slog.Duration("liveness_horizon", settings.livenessHorizon),
		slog.Duration("liveness_backdating", settings.livenessBackdating),
		slog.Any("permissions_not_shown_to_callers", control.Unnamed()),
		slog.String("renewal_address", renewals.Address()),
		slog.String("agent_authority", authority.Subject()),
		slog.Time("agent_authority_expires_at", authority.NotAfter()),
		slog.Duration("agent_certificate_lifetime", settings.certificateLife),
	)

	platform.Health().Register("backbone", published.publisher.Ping)
	platform.Health().Register("alert-store", raised.Ping)
	platform.Health().Register("telemetry-store", seen.Ping)
	platform.Add(published.follower(platform.Logger()))
	platform.Add(listener)
	platform.Add(renewals)
	platform.Add(announcer)
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

// The renewal listener terminates the agent trust domain and the one above it
// terminates the operator domain, so an agent key cannot reach the administrative
// surface and an operator key cannot renew an agent's certificate.
func agentTransport(settings configuration) (*tls.Config, error) {
	material, err := tlsx.NewMaterial(settings.renewalCertFile, settings.renewalKeyFile, settings.agentCAFile)
	if err != nil {
		return nil, err
	}
	return material.MutualServerConfig()
}

// The private key is read once and kept in this process. A control plane that
// cannot read the authority it signs with does not serve, because an estate whose
// certificates silently stopped being renewable expires all at once.
func agentAuthority(settings configuration) (*pki.Authority, func() ([]byte, error), error) {
	certificatePEM, err := os.ReadFile(settings.authorityFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read the agent authority certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(settings.authorityKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read the agent authority key: %w", err)
	}
	authority, err := pki.NewAuthority(certificatePEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	bundle := func() ([]byte, error) {
		read, err := os.ReadFile(settings.trustBundleFile)
		if err != nil {
			return nil, fmt.Errorf("read the agent trust bundle: %w", err)
		}
		return read, nil
	}
	held, err := bundle()
	if err != nil {
		return nil, nil, err
	}
	if err := pki.Trusts(held, authority); err != nil {
		return nil, nil, err
	}
	return authority, bundle, nil
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
	reader    *broker.StateLog
}

func publishedRulesets(ctx context.Context, settings configuration, platform *service.Service) (rulesetLog, error) {
	publisher, err := broker.NewRulesets(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Rulesets.Name,
		ClientID: serviceName,
		Security: settings.security,
	})
	if err != nil {
		return rulesetLog{}, err
	}

	reader, err := broker.NewStateLog(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Rulesets.Name,
		ClientID: serviceName,
		Security: settings.security,
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
			if err := l.catalogue.Read(record.Value, broker.Desired(record.Key)); err != nil {
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
	reader  *broker.StateLog
	deliver broker.Deliver
}

func (f follower) Name() string { return "ruleset-log" }

func (f follower) Run(ctx context.Context) error {
	if err := f.reader.Follow(ctx, f.deliver); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
