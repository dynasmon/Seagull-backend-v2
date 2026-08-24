package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "analysis-engine"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	group    string
	rules    string

	batchEvents  int
	fetchMaxWait time.Duration
	startTimeout time.Duration
}

// The engine reads the same topic as the writer under a group of its own, so
// the two advance independently and neither can hold the other back.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		group:    parser.String("SEAGULL_ANALYSIS_CONSUMER_GROUP", serviceName),
		rules:    parser.FilePath("SEAGULL_DETECTION_RULES", "/etc/seagull/rules"),

		batchEvents:  parser.Int("SEAGULL_ANALYSIS_BATCH_EVENTS", 5_000, 1, 100_000),
		fetchMaxWait: parser.Duration("SEAGULL_ANALYSIS_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		startTimeout: parser.Duration("SEAGULL_ANALYSIS_START_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
	}

	return loaded, parser.Err()
}
