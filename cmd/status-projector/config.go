package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "status-projector"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	security broker.Security
	group    string

	batchRecords  int
	fetchMaxWait  time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration

	store clickhouse.Config
}

// A report is a few kilobytes and a fleet sends one per agent every interval,
// so a batch is counted generously in reports.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		security: broker.LoadSecurity(parser),
		group:    parser.String("SEAGULL_STATUS_PROJECTOR_CONSUMER_GROUP", serviceName),

		batchRecords:  parser.Int("SEAGULL_STATUS_PROJECTOR_BATCH_RECORDS", 512, 1, 10_000),
		fetchMaxWait:  parser.Duration("SEAGULL_STATUS_PROJECTOR_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:    parser.Duration("SEAGULL_STATUS_PROJECTOR_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay: parser.Duration("SEAGULL_STATUS_PROJECTOR_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		store: clickhouse.LoadConfig("SEAGULL_STATUS_STORE", parser),
	}

	return loaded, parser.Err()
}
