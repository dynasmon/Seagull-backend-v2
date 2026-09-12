package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "inventory-projector"

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

// A batch is counted in records and not in items, and it is small because each
// record is a whole scan: sixty-four of them can be half a million packages.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		security: broker.LoadSecurity(parser),
		group:    parser.String("SEAGULL_INVENTORY_PROJECTOR_CONSUMER_GROUP", serviceName),

		batchRecords:  parser.Int("SEAGULL_INVENTORY_PROJECTOR_BATCH_RECORDS", 64, 1, 10_000),
		fetchMaxWait:  parser.Duration("SEAGULL_INVENTORY_PROJECTOR_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:    parser.Duration("SEAGULL_INVENTORY_PROJECTOR_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay: parser.Duration("SEAGULL_INVENTORY_PROJECTOR_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		store: clickhouse.LoadConfig("SEAGULL_INVENTORY_STORE", parser),
	}

	return loaded, parser.Err()
}
