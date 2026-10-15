package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "assessment-projector"

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

// An assessment is at most a few hundred kilobytes and an agent sends one when
// its posture changed and once a day otherwise, so a batch is counted in fewer
// records than a status batch is.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		security: broker.LoadSecurity(parser),
		group:    parser.String("SEAGULL_ASSESSMENT_PROJECTOR_CONSUMER_GROUP", serviceName),

		batchRecords:  parser.Int("SEAGULL_ASSESSMENT_PROJECTOR_BATCH_RECORDS", 128, 1, 10_000),
		fetchMaxWait:  parser.Duration("SEAGULL_ASSESSMENT_PROJECTOR_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:    parser.Duration("SEAGULL_ASSESSMENT_PROJECTOR_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay: parser.Duration("SEAGULL_ASSESSMENT_PROJECTOR_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		store: clickhouse.LoadConfig("SEAGULL_ASSESSMENT_STORE", parser),
	}

	return loaded, parser.Err()
}
