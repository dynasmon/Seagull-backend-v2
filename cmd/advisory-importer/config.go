package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const serviceName = "advisory-importer"

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	security broker.Security

	feeds     []string
	export    string
	authority string

	interval     time.Duration
	retryDelay   time.Duration
	backoff      time.Duration
	fetchTimeout time.Duration
	attempts     int
	concurrency  int
	batch        int

	maxIndexBytes  int64
	maxRecordBytes int64

	replayRecords int
	startTimeout  time.Duration
}

// Which feeds to follow is a deployment's choice and has no default: each one
// is thousands of requests the first time it is read, and it is only worth them
// on an estate that runs that distribution.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		security: broker.LoadSecurity(parser),

		feeds:     parser.RequiredList("SEAGULL_ADVISORY_FEEDS"),
		export:    parser.String("SEAGULL_ADVISORY_OSV_EXPORT", "https://osv-vulnerabilities.storage.googleapis.com"),
		authority: parser.FilePath("SEAGULL_ADVISORY_OSV_CA", ""),

		interval:     parser.Duration("SEAGULL_ADVISORY_SYNC_INTERVAL", time.Hour, time.Minute, 24*time.Hour),
		retryDelay:   parser.Duration("SEAGULL_ADVISORY_SYNC_RETRY_DELAY", time.Minute, time.Second, 24*time.Hour),
		backoff:      parser.Duration("SEAGULL_ADVISORY_FETCH_BACKOFF", time.Second, 10*time.Millisecond, time.Minute),
		fetchTimeout: parser.Duration("SEAGULL_ADVISORY_FETCH_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		attempts:     parser.Int("SEAGULL_ADVISORY_FETCH_ATTEMPTS", 3, 1, 10),
		concurrency:  parser.Int("SEAGULL_ADVISORY_FETCH_CONCURRENCY", 8, 1, 32),
		batch:        parser.Int("SEAGULL_ADVISORY_PUBLISH_BATCH", 64, 1, 1_000),

		maxIndexBytes:  parser.Bytes("SEAGULL_ADVISORY_MAX_INDEX_BYTES", 64<<20, 1<<20, 1<<30),
		maxRecordBytes: parser.Bytes("SEAGULL_ADVISORY_MAX_RECORD_BYTES", 4<<20, 64<<10, 64<<20),

		replayRecords: parser.Int("SEAGULL_ADVISORY_REPLAY_RECORDS", 1_000, 1, 100_000),
		startTimeout:  parser.Duration("SEAGULL_ADVISORY_START_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
	}

	return loaded, parser.Err()
}
