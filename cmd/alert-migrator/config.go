package main

import (
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
)

const serviceName = "alert-migrator"

type configuration struct {
	logLevel  string
	logFormat string
	store     postgres.Config
}

// Applies a schema and exits, so it takes none of the settings that describe a
// long-running service.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		logLevel:  parser.Enum("SEAGULL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		logFormat: parser.Enum("SEAGULL_LOG_FORMAT", log.FormatJSON, log.FormatJSON, log.FormatText),
		store:     postgres.LoadConfig("SEAGULL_ALERT_STORE", parser),
	}

	return loaded, parser.Err()
}
