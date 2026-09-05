package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/detectionstate"
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

	logRecords   int
	batchEvents  int
	fetchMaxWait time.Duration
	startTimeout time.Duration

	publishTimeout time.Duration
	retryDelay     time.Duration
	maxRetryDelay  time.Duration

	state detectionstate.Bounds
	sole  bool
	skew  time.Duration
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

		logRecords:   parser.Int("SEAGULL_ANALYSIS_RULESET_RECORDS", 256, 1, 10_000),
		batchEvents:  parser.Int("SEAGULL_ANALYSIS_BATCH_EVENTS", 5_000, 1, 100_000),
		fetchMaxWait: parser.Duration("SEAGULL_ANALYSIS_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		startTimeout: parser.Duration("SEAGULL_ANALYSIS_START_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),

		publishTimeout: parser.Duration("SEAGULL_DETECTION_PUBLISH_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		retryDelay:     parser.Duration("SEAGULL_DETECTION_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay:  parser.Duration("SEAGULL_DETECTION_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		// The product of the last two is the whole of what a counting rule may
		// occupy, and the first is what a restart costs: rebuilding state means
		// reading that much of the backbone again.
		state: detectionstate.Bounds{
			Window:             parser.Duration("SEAGULL_DETECTION_STATE_WINDOW", time.Hour, time.Minute, detectionstate.MaxWindow),
			ObservationsPerKey: parser.Int("SEAGULL_DETECTION_STATE_OBSERVATIONS", 128, 2, detectionstate.MaxObservationsPerKey),
			Keys:               parser.Int("SEAGULL_DETECTION_STATE_KEYS", 4096, 1, detectionstate.MaxKeys),
		},

		// Checked against the assignment rather than trusted.
		sole: parser.Bool("SEAGULL_DETECTION_STATE_SOLE_READER", false),
		skew: parser.Duration("SEAGULL_EVENT_MAX_CLOCK_SKEW", 5*time.Minute, time.Second, time.Hour),
	}

	return loaded, parser.Err()
}
