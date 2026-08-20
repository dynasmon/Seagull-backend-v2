package main

import (
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
)

const serviceName = "backbone-migrator"

type configuration struct {
	logLevel  string
	logFormat string
	brokers   []string
	topology  broker.Topology
}

// Provisions the backbone and exits, so it takes none of the settings that
// describe a long-running service.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		logLevel:  parser.Enum("SEAGULL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		logFormat: parser.Enum("SEAGULL_LOG_FORMAT", log.FormatJSON, log.FormatJSON, log.FormatText),
		brokers:   parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology:  broker.LoadTopology(parser),
	}

	return loaded, parser.Err()
}
