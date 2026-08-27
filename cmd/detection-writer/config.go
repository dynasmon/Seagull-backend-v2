package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "detection-writer"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	group    string

	batchDetections int
	fetchMaxWait    time.Duration
	retryDelay      time.Duration
	maxRetryDelay   time.Duration

	store clickhouse.Config
}

// A batch is smaller than the writer's, because detections are rarer than the
// telemetry they are made from and waiting to fill five thousand of them would
// keep the first one out of the store for longer than anyone would accept.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		group:    parser.String("SEAGULL_DETECTION_WRITER_CONSUMER_GROUP", serviceName),

		batchDetections: parser.Int("SEAGULL_DETECTION_WRITER_BATCH_DETECTIONS", 500, 1, 100_000),
		fetchMaxWait:    parser.Duration("SEAGULL_DETECTION_WRITER_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:      parser.Duration("SEAGULL_DETECTION_WRITER_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay:   parser.Duration("SEAGULL_DETECTION_WRITER_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		store: storeConfig(parser),
	}

	return loaded, parser.Err()
}

// Its own configuration, pointing at the same server as the event writer's by
// default. Two processes choosing the same adapter is not the same as sharing
// one, and an operator who moves detections to a cluster of their own should not
// have to move telemetry with them.
func storeConfig(parser *config.Parser) clickhouse.Config {
	return clickhouse.Config{
		Address:  parser.RequiredString("SEAGULL_DETECTION_STORE_ADDRESS"),
		Database: parser.String("SEAGULL_DETECTION_STORE_DATABASE", "seagull"),
		User:     parser.String("SEAGULL_DETECTION_STORE_USER", "seagull"),
		Password: parser.Secret("SEAGULL_DETECTION_STORE_PASSWORD"),
		Timeout:  parser.Duration("SEAGULL_DETECTION_STORE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
	}
}
