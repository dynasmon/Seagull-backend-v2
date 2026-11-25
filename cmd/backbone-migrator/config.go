package main

import (
	"errors"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/log"
)

const serviceName = "backbone-migrator"

type configuration struct {
	logLevel   string
	logFormat  string
	brokers    []string
	topology   broker.Topology
	security   broker.Security
	principals string
}

// Provisions the backbone and exits, so it takes none of the settings that
// describe a long-running service. A backbone that authenticates is given its
// components' principals here and nowhere else.
func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		logLevel:   parser.Enum("SEAGULL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		logFormat:  parser.Enum("SEAGULL_LOG_FORMAT", log.FormatJSON, log.FormatJSON, log.FormatText),
		brokers:    parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology:   broker.LoadTopology(parser),
		security:   broker.LoadSecurity(parser, serviceName),
		principals: parser.FilePath("SEAGULL_BACKBONE_PRINCIPALS_DIR", ""),
	}
	if err := parser.Err(); err != nil {
		return loaded, err
	}

	switch {
	case loaded.security.Authenticated() && loaded.principals == "":
		return loaded, errors.New("invalid configuration: SEAGULL_BACKBONE_PRINCIPALS_DIR is required when the backbone authenticates, because every component's principal is made here")
	case !loaded.security.Authenticated() && loaded.principals != "":
		return loaded, errors.New("invalid configuration: SEAGULL_BACKBONE_PRINCIPALS_DIR was given and the backbone authenticates nobody")
	}
	return loaded, nil
}
