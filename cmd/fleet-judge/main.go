package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/fleetjudge"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/config"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/run"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
)

func main() {
	ctx, stop := run.SignalContext(context.Background())
	defer stop()

	if err := judge(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "fleet-judge: %v\n", err)
		os.Exit(1)
	}
}

// The process that decides what agents' reports, and their absence, say about
// them. It reads every log it judges from whole, as a gateway reads the agent
// log, so a second judge decides the same findings under the same names, and it
// writes nothing but its decisions: an outage of it costs how current findings
// are, and never anything an agent sends.
func judge(ctx context.Context) error {
	settings, err := load(config.FromEnvironment())
	if err != nil {
		return err
	}

	platform, err := service.New(settings.service)
	if err != nil {
		return err
	}

	decisions, err := broker.NewAgentFindings(broker.Config{
		Brokers:         settings.brokers,
		Topic:           settings.topology.AgentFindings.Name,
		MaxMessageBytes: settings.topology.AgentFindings.MaxMessageBytes,
		ClientID:        serviceName,
		Security:        settings.security,
	})
	if err != nil {
		return err
	}
	defer decisions.Close()

	// The topology is applied by backbone-migrator, never here. This only refuses
	// to judge when a log it reads or writes is missing or reshaped.
	topologyCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()
	read := []broker.Topic{settings.topology.Status, settings.topology.Agents, settings.topology.Gateways, settings.topology.AgentFindings,
		settings.topology.Refusals}
	drift, err := decisions.VerifyTopics(topologyCtx, read...)
	if err != nil {
		return err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}
	broker.LogDurability(ctx, platform.Logger(), settings.topology.AgentFindings)
	broker.ObserveDurability(platform.Metrics(), settings.topology.AgentFindings)

	logs := make(map[string]whole, len(read))
	for _, topic := range read {
		reader, err := broker.NewStateLog(broker.Config{
			Brokers:  settings.brokers,
			Topic:    topic.Name,
			ClientID: serviceName,
			Security: settings.security,
		}, settings.logRecords)
		if err != nil {
			return err
		}
		defer reader.Close()
		logs[topic.Name] = whole{reader: reader}
	}

	component, err := fleetjudge.New(fleetjudge.Options{
		Status:     logs[settings.topology.Status.Name],
		Admissions: logs[settings.topology.Agents.Name],
		Beacons:    logs[settings.topology.Gateways.Name],
		Findings:   logs[settings.topology.AgentFindings.Name],
		Refusals:   logs[settings.topology.Refusals.Name],
		Decisions:  decisions,
		Metrics:    fleetjudge.NewMetrics(platform.Metrics()),
		Logger:     platform.Logger(),
		Every:      settings.every,
		StaleAfter: settings.staleAfter,
		MaxAgents:  settings.maxAgents,
		Again:      again,
	})
	if err != nil {
		return err
	}

	platform.Health().Register("backbone", decisions.Ping)
	platform.Add(component)

	platform.Logger().Info("fleet_judge_configured",
		slog.String("status_topic", settings.topology.Status.Name),
		slog.String("agents_topic", settings.topology.Agents.Name),
		slog.String("gateways_topic", settings.topology.Gateways.Name),
		slog.String("findings_topic", settings.topology.AgentFindings.Name),
		slog.String("refusals_topic", settings.topology.Refusals.Name),
		slog.Duration("interval", settings.every),
		slog.Duration("stale_after", settings.staleAfter),
		slog.Int("max_agents", settings.maxAgents),
	)

	return platform.Run(ctx)
}
