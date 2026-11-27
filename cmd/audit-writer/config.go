package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "audit-writer"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	security broker.Security

	batchRecords  int
	fetchMaxWait  time.Duration
	retryDelay    time.Duration
	maxRetryDelay time.Duration

	store clickhouse.Config
}

// An audit event is a few hundred bytes, and a batch costs two reads of the
// store before its insert, so a batch is small and the fetch waits for more.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		security: broker.LoadSecurity(parser, serviceName),

		batchRecords:  parser.Int("SEAGULL_AUDIT_WRITER_BATCH_RECORDS", 256, 1, 10_000),
		fetchMaxWait:  parser.Duration("SEAGULL_AUDIT_WRITER_FETCH_MAX_WAIT", time.Second, 10*time.Millisecond, time.Minute),
		retryDelay:    parser.Duration("SEAGULL_AUDIT_WRITER_RETRY_DELAY", time.Second, 100*time.Millisecond, time.Minute),
		maxRetryDelay: parser.Duration("SEAGULL_AUDIT_WRITER_RETRY_DELAY_MAX", 30*time.Second, time.Second, 10*time.Minute),

		store: clickhouse.LoadConfig("SEAGULL_AUDIT_STORE", parser),
	}

	return loaded, parser.Err()
}
