package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/pki"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
)

const serviceName = "control-api"

type configuration struct {
	service service.Config

	address         string
	certificateFile string
	keyFile         string
	callerCAFile    string

	authorityFile       string
	authorityKeyFile    string
	trustBundleFile     string
	certificateLife     time.Duration
	renewalAddress      string
	renewalCertFile     string
	renewalKeyFile      string
	agentCAFile         string
	renewalsPerSecond   float64
	renewalBurst        int
	trackedRenewalAgent int

	brokers      []string
	topology     broker.Topology
	security     broker.Security
	startTimeout time.Duration
	logRecords   int

	policyFile     string
	sessionKey     config.Secret
	sessionLife    time.Duration
	sessionsPer    int
	sessionsTotal  int
	ratePerSecond  float64
	rateBurst      int
	trackedCallers int

	alerts    postgres.Config
	telemetry clickhouse.Config

	livenessHorizon    time.Duration
	livenessBackdating time.Duration
	announceEvery      time.Duration
	announceBatch      int

	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		address:         parser.String("SEAGULL_CONTROL_API_ADDRESS", "127.0.0.1:8445"),
		certificateFile: parser.RequiredFilePath("SEAGULL_CONTROL_API_TLS_CERT"),
		keyFile:         parser.RequiredFilePath("SEAGULL_CONTROL_API_TLS_KEY"),
		callerCAFile:    parser.RequiredFilePath("SEAGULL_CONTROL_API_CALLER_CA"),

		authorityFile:    parser.RequiredFilePath("SEAGULL_CONTROL_API_AGENT_AUTHORITY_CERT"),
		authorityKeyFile: parser.RequiredFilePath("SEAGULL_CONTROL_API_AGENT_AUTHORITY_KEY"),
		trustBundleFile:  parser.RequiredFilePath("SEAGULL_CONTROL_API_AGENT_TRUST_BUNDLE"),
		certificateLife: parser.Duration("SEAGULL_CONTROL_API_AGENT_CERT_LIFETIME",
			7*24*time.Hour, pki.MinValidity, pki.MaxValidity),
		renewalAddress:      parser.String("SEAGULL_CONTROL_API_RENEWAL_ADDRESS", "127.0.0.1:8446"),
		renewalCertFile:     parser.RequiredFilePath("SEAGULL_CONTROL_API_RENEWAL_TLS_CERT"),
		renewalKeyFile:      parser.RequiredFilePath("SEAGULL_CONTROL_API_RENEWAL_TLS_KEY"),
		agentCAFile:         parser.RequiredFilePath("SEAGULL_CONTROL_API_AGENT_CA"),
		renewalBurst:        parser.Int("SEAGULL_CONTROL_API_RENEWAL_BURST", 4, 1, 1_000),
		trackedRenewalAgent: parser.Int("SEAGULL_CONTROL_API_TRACKED_RENEWING_AGENTS", 8192, 1, 1_000_000),

		brokers:      parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology:     broker.LoadTopology(parser),
		security:     broker.LoadSecurity(parser),
		startTimeout: parser.Duration("SEAGULL_CONTROL_API_START_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		logRecords:   parser.Int("SEAGULL_CONTROL_API_RULESET_RECORDS", 256, 1, 10_000),

		policyFile:     parser.RequiredFilePath("SEAGULL_CONTROL_API_POLICY"),
		sessionKey:     parser.Secret("SEAGULL_CONTROL_API_SESSION_KEY"),
		sessionLife:    parser.Duration("SEAGULL_CONTROL_API_SESSION_LIFETIME", 15*time.Minute, time.Minute, 24*time.Hour),
		sessionsPer:    parser.Int("SEAGULL_CONTROL_API_SESSIONS_PER_CALLER", 8, 1, 64),
		sessionsTotal:  parser.Int("SEAGULL_CONTROL_API_SESSIONS_MAX", 4096, 1, 1_000_000),
		rateBurst:      parser.Int("SEAGULL_CONTROL_API_RATE_BURST", 40, 1, 100_000),
		trackedCallers: parser.Int("SEAGULL_CONTROL_API_TRACKED_CALLERS", 4096, 1, 1_000_000),

		alerts:    postgres.LoadConfig("SEAGULL_ALERT_STORE", parser),
		telemetry: clickhouse.LoadConfig("SEAGULL_CONTROL_TELEMETRY_STORE", parser),

		livenessHorizon: parser.Duration("SEAGULL_CONTROL_API_LIVENESS_HORIZON",
			clickhouse.DefaultLivenessHorizon, time.Hour, 365*24*time.Hour),
		livenessBackdating: parser.Duration("SEAGULL_CONTROL_API_LIVENESS_BACKDATING",
			clickhouse.DefaultLivenessBackdating, 0, 365*24*time.Hour),
		announceEvery: parser.Duration("SEAGULL_CONTROL_API_ANNOUNCE_INTERVAL", 30*time.Second, time.Second, time.Hour),
		announceBatch: parser.Int("SEAGULL_CONTROL_API_ANNOUNCE_BATCH", 100, 1, 500),

		readTimeout:  parser.Duration("SEAGULL_CONTROL_API_READ_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		writeTimeout: parser.Duration("SEAGULL_CONTROL_API_WRITE_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		idleTimeout:  parser.Duration("SEAGULL_CONTROL_API_IDLE_TIMEOUT", 60*time.Second, time.Second, 30*time.Minute),
	}

	loaded.ratePerSecond = float64(parser.Int("SEAGULL_CONTROL_API_RATE_PER_SECOND", 20, 0, 10_000))
	loaded.renewalsPerSecond = 1 / parser.Duration("SEAGULL_CONTROL_API_RENEWAL_INTERVAL",
		time.Minute, time.Second, 24*time.Hour).Seconds()

	if err := parser.Err(); err != nil {
		return configuration{}, err
	}
	return loaded, nil
}
