package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "control-api"

type configuration struct {
	service service.Config

	address         string
	certificateFile string
	keyFile         string
	callerCAFile    string

	brokers      []string
	topology     broker.Topology
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

		brokers:      parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology:     broker.LoadTopology(parser),
		startTimeout: parser.Duration("SEAGULL_CONTROL_API_START_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		logRecords:   parser.Int("SEAGULL_CONTROL_API_RULESET_RECORDS", 256, 1, 10_000),

		policyFile:     parser.RequiredFilePath("SEAGULL_CONTROL_API_POLICY"),
		sessionKey:     parser.Secret("SEAGULL_CONTROL_API_SESSION_KEY"),
		sessionLife:    parser.Duration("SEAGULL_CONTROL_API_SESSION_LIFETIME", 15*time.Minute, time.Minute, 24*time.Hour),
		sessionsPer:    parser.Int("SEAGULL_CONTROL_API_SESSIONS_PER_CALLER", 8, 1, 64),
		sessionsTotal:  parser.Int("SEAGULL_CONTROL_API_SESSIONS_MAX", 4096, 1, 1_000_000),
		rateBurst:      parser.Int("SEAGULL_CONTROL_API_RATE_BURST", 40, 1, 100_000),
		trackedCallers: parser.Int("SEAGULL_CONTROL_API_TRACKED_CALLERS", 4096, 1, 1_000_000),

		readTimeout:  parser.Duration("SEAGULL_CONTROL_API_READ_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		writeTimeout: parser.Duration("SEAGULL_CONTROL_API_WRITE_TIMEOUT", 15*time.Second, time.Second, 5*time.Minute),
		idleTimeout:  parser.Duration("SEAGULL_CONTROL_API_IDLE_TIMEOUT", 60*time.Second, time.Second, 30*time.Minute),
	}

	loaded.ratePerSecond = float64(parser.Int("SEAGULL_CONTROL_API_RATE_PER_SECOND", 20, 0, 10_000))

	if err := parser.Err(); err != nil {
		return configuration{}, err
	}
	return loaded, nil
}
