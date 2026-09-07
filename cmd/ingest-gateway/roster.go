package main

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/protobuf/proto"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/broker"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/service"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// Which agents the platform still honours, read whole before this process
// admits anything and followed afterwards: a gateway that had seen half the log
// would admit an agent somebody revoked while it was starting.
type roster struct {
	held   *agent.Roster
	reader *broker.StateLog
}

func admissible(ctx context.Context, settings configuration, platform *service.Service) (roster, error) {
	reader, err := broker.NewStateLog(broker.Config{
		Brokers:  settings.brokers,
		Topic:    settings.topology.Agents.Name,
		ClientID: settings.admissionRules.Gateway,
		Security: settings.security,
	}, settings.rosterRecords)
	if err != nil {
		return roster{}, err
	}

	held := roster{held: agent.NewRoster(), reader: reader}

	startCtx, cancel := context.WithTimeout(ctx, settings.startTimeout)
	defer cancel()

	drift, err := reader.VerifyTopics(startCtx, settings.topology.Agents)
	if err != nil {
		held.close()
		return roster{}, err
	}
	for _, entry := range drift {
		platform.Logger().Warn("backbone_topology_drift", slog.String("drift", entry))
	}
	if err := reader.Replay(startCtx, held.applying(platform.Logger())); err != nil {
		held.close()
		return roster{}, err
	}
	return held, nil
}

// A record that cannot be read is counted and stepped over rather than allowed
// to end the replay: one unreadable admission must not stop every agent in the
// estate from sending.
func (r roster) applying(logger *slog.Logger) broker.Deliver {
	return func(_ context.Context, records []broker.Record) error {
		for _, record := range records {
			var admission agentv1.Admission
			if err := proto.Unmarshal(record.Value, &admission); err != nil {
				logger.Warn("agent_admission_refused",
					slog.Int64("offset", record.Offset),
					slog.String("key", string(record.Key)),
					slog.String("error", err.Error()),
				)
				continue
			}
			if err := r.held.Apply(&admission); err != nil {
				logger.Warn("agent_admission_refused",
					slog.Int64("offset", record.Offset),
					slog.String("key", string(record.Key)),
					slog.String("error", err.Error()),
				)
			}
		}
		return nil
	}
}

func (r roster) follower(logger *slog.Logger) follower {
	return follower{reader: r.reader, deliver: r.applying(logger)}
}

func (r roster) close() {
	if r.reader != nil {
		r.reader.Close()
	}
}

type follower struct {
	reader  *broker.StateLog
	deliver broker.Deliver
}

func (f follower) Name() string { return "agent-roster" }

func (f follower) Run(ctx context.Context) error {
	if err := f.reader.Follow(ctx, f.deliver); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
