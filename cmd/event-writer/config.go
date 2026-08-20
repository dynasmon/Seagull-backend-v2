package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "event-writer"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	group    string

	batchEvents   int
	fetchMaxWait  time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration

	store clickhouse.Config
}

func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		group:    parser.String("SEAGULL_WRITER_CONSUMER_GROUP", serviceName),

		batchEvents:   parser.Int("SEAGULL_WRITER_BATCH_EVENTS", 5_000, 1, 100_000),
		fetchMaxWait:  parser.Duration("SEAGULL_WRITER_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:    parser.Duration("SEAGULL_WRITER_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay: parser.Duration("SEAGULL_WRITER_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		store: storeConfig(parser),
	}

	return loaded, parser.Err()
}

// The first real secret in this repository, and so the first user of
// `config.Secret` and the `_FILE` convention.
func storeConfig(parser *config.Parser) clickhouse.Config {
	return clickhouse.Config{
		Address:  parser.RequiredString("SEAGULL_EVENT_STORE_ADDRESS"),
		Database: parser.String("SEAGULL_EVENT_STORE_DATABASE", "seagull"),
		User:     parser.String("SEAGULL_EVENT_STORE_USER", "seagull"),
		Password: parser.Secret("SEAGULL_EVENT_STORE_PASSWORD"),
		Timeout:  parser.Duration("SEAGULL_EVENT_STORE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
	}
}
