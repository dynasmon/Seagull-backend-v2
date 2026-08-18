package main

import (
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
)

const serviceName = "store-migrator"

type configuration struct {
	logLevel  string
	logFormat string
	store     clickhouse.Config
}

// Applies a schema and exits, so it takes none of the settings that describe a
// long-running service.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		logLevel:  parser.Enum("SEAGULL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		logFormat: parser.Enum("SEAGULL_LOG_FORMAT", log.FormatJSON, log.FormatJSON, log.FormatText),
		store: clickhouse.Config{
			Address:  parser.RequiredString("SEAGULL_EVENT_STORE_ADDRESS"),
			Database: parser.String("SEAGULL_EVENT_STORE_DATABASE", "seagull"),
			User:     parser.String("SEAGULL_EVENT_STORE_USER", "seagull"),
			Password: parser.Secret("SEAGULL_EVENT_STORE_PASSWORD"),
			Timeout:  parser.Duration("SEAGULL_EVENT_STORE_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
		},
	}

	return loaded, parser.Err()
}
