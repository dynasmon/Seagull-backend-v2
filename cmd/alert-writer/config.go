package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
)

const serviceName = "alert-writer"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	group    string

	batchDetections int
	fetchMaxWait    time.Duration
	retryDelay      time.Duration
	maxRetryDelay   time.Duration

	floor string
	store postgres.Config
}

// The floor is the one product decision this process makes, so it is a setting
// rather than a constant: an estate that wants every finding in front of
// somebody lowers it, and one drowning in noise raises it.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		group:    parser.String("SEAGULL_ALERT_WRITER_CONSUMER_GROUP", serviceName),

		batchDetections: parser.Int("SEAGULL_ALERT_WRITER_BATCH_DETECTIONS", 500, 1, 100_000),
		fetchMaxWait:    parser.Duration("SEAGULL_ALERT_WRITER_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:      parser.Duration("SEAGULL_ALERT_WRITER_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay:   parser.Duration("SEAGULL_ALERT_WRITER_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		floor: parser.Enum("SEAGULL_ALERT_SEVERITY_FLOOR", "medium", "low", "medium", "high", "critical"),
		store: postgres.LoadConfig("SEAGULL_ALERT_STORE", parser),
	}

	return loaded, parser.Err()
}
