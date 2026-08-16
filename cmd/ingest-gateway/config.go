package main

import (
	"time"

	"github.com/dynasmon/Seagull-v2/internal/event"
	"github.com/dynasmon/Seagull-v2/internal/ingest"
	"github.com/dynasmon/Seagull-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-v2/internal/platform/service"
)

const serviceName = "ingest-gateway"

type configuration struct {
	service service.Config

	address         string
	certificateFile string
	keyFile         string
	agentCAFile     string

	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration

	maxBodyBytes   int64
	publishTimeout time.Duration

	ratePerSecond  float64
	rateBurst      int
	trackedAgents  int
	admissionRules ingest.Policy

	brokers []string
	topic   string
}

func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		address:         parser.String("SEAGULL_GATEWAY_ADDRESS", "0.0.0.0:8443"),
		certificateFile: parser.RequiredFilePath("SEAGULL_GATEWAY_TLS_CERT"),
		keyFile:         parser.RequiredFilePath("SEAGULL_GATEWAY_TLS_KEY"),
		agentCAFile:     parser.RequiredFilePath("SEAGULL_GATEWAY_AGENT_CA"),

		readTimeout:  parser.Duration("SEAGULL_GATEWAY_READ_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		writeTimeout: parser.Duration("SEAGULL_GATEWAY_WRITE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		idleTimeout:  parser.Duration("SEAGULL_GATEWAY_IDLE_TIMEOUT", 90*time.Second, time.Second, 30*time.Minute),

		maxBodyBytes:   parser.Bytes("SEAGULL_GATEWAY_MAX_BODY", 8<<20, 64<<10, 64<<20),
		publishTimeout: parser.Duration("SEAGULL_GATEWAY_PUBLISH_TIMEOUT", 10*time.Second, time.Second, time.Minute),

		rateBurst:     parser.Int("SEAGULL_GATEWAY_RATE_BURST", 400, 1, 1_000_000),
		trackedAgents: parser.Int("SEAGULL_GATEWAY_RATE_TRACKED_AGENTS", 10_000, 1, 1_000_000),

		brokers: parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topic:   parser.String("SEAGULL_BACKBONE_EVENTS_TOPIC", "security.events.raw"),
	}

	loaded.ratePerSecond = float64(parser.Int("SEAGULL_GATEWAY_RATE_PER_SECOND", 200, 0, 1_000_000))
	loaded.admissionRules = ingest.Policy{
		Gateway:           parser.String("SEAGULL_GATEWAY_ID", serviceName),
		TenantID:          parser.String("SEAGULL_TENANT_ID", "default"),
		MaxEventsPerBatch: parser.Int("SEAGULL_GATEWAY_MAX_EVENTS_PER_BATCH", 10_000, 1, 100_000),
		Event: event.Policy{
			MaxClockSkew: parser.Duration("SEAGULL_EVENT_MAX_CLOCK_SKEW", 5*time.Minute, time.Second, time.Hour),
			MaxAge:       parser.Duration("SEAGULL_EVENT_MAX_AGE", 168*time.Hour, time.Minute, 8760*time.Hour),
		},
	}

	return loaded, parser.Err()
}
