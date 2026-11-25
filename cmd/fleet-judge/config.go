package main

import (
	"fmt"
	"time"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

const (
	serviceName = "fleet-judge"

	// The decisions topic keeps at least two days, so a finding decided again
	// every day always has its newest decision on it for a judge to read back.
	again = 24 * time.Hour
)

type configuration struct {
	service service.Config

	brokers  []string
	topology broker.Topology
	security broker.Security

	every        time.Duration
	staleAfter   time.Duration
	maxAgents    int
	logRecords   int
	startTimeout time.Duration
}

func load(parser *config.Parser) (configuration, error) {
	loaded := configuration{
		service: service.LoadConfig(serviceName, parser),

		brokers:  parser.RequiredList("SEAGULL_BACKBONE_BROKERS"),
		topology: broker.LoadTopology(parser),
		security: broker.LoadSecurity(parser, serviceName),

		every:        parser.Duration("SEAGULL_FLEET_JUDGE_INTERVAL", 5*time.Second, time.Second, time.Minute),
		staleAfter:   parser.Duration("SEAGULL_FLEET_JUDGE_STALE_AFTER", 30*time.Second, 2*time.Second, 10*time.Minute),
		maxAgents:    parser.Int("SEAGULL_FLEET_JUDGE_MAX_AGENTS", 200_000, 1, 10_000_000),
		logRecords:   parser.Int("SEAGULL_FLEET_JUDGE_LOG_RECORDS", 1_000, 1, 100_000),
		startTimeout: parser.Duration("SEAGULL_FLEET_JUDGE_START_TIMEOUT", 30*time.Second, time.Second, 5*time.Minute),
	}
	if err := parser.Err(); err != nil {
		return loaded, err
	}
	if loaded.staleAfter < 2*loaded.every {
		return loaded, fmt.Errorf(
			"invalid configuration: SEAGULL_FLEET_JUDGE_STALE_AFTER is %s and must outlast two SEAGULL_FLEET_JUDGE_INTERVAL of %s",
			loaded.staleAfter, loaded.every)
	}
	return loaded, nil
}
