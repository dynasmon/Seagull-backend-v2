package control

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	assessmentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/assessment/v1"
)

// When telemetry from an agent last reached the platform, asked of wherever it
// landed. It is not part of the registry: an agent sends continuously and is
// registered once, so keeping it beside what was decided would put a write on
// the ingest path to record something the stream already says.
type Liveness interface {
	LastSeen(ctx context.Context, agents, tenants []string) (map[string]time.Time, error)
}

// The newest status report of each agent, asked of where the status projector
// keeps it, for the same reason and with the same bounds as LastSeen.
type Reports interface {
	Newest(ctx context.Context, agents, tenants []string) (map[string]agentstatus.Report, error)
}

// The newest assessment of each agent, which is its posture, asked of where the
// assessment projector keeps every one, for the same reason and with the same
// bounds as LastSeen.
type Postures interface {
	Postures(ctx context.Context, agents, tenants []string) (map[string]*assessmentv1.Assessment, error)
}

// A failure here costs the caller the observed columns and not the answer: the
// registry holds what was decided, and what agents send lands in stores that
// may be slower or absent without making an agent unreadable. A page carries
// how recently each agent reported; the report itself and the agent's posture
// are carried when one agent is read.
func (s *Server) observed(ctx context.Context, listed []*agentv1.Agent, tenants []string, whole bool) {
	if len(listed) == 0 {
		return
	}

	asked := make([]string, 0, len(listed))
	for _, one := range listed {
		asked = append(asked, one.GetAgentId())
	}

	if s.liveness != nil {
		if seen, err := s.liveness.LastSeen(ctx, asked, tenants); err != nil {
			s.logger.Warn("agent_liveness_unavailable", slog.String("error", err.Error()))
		} else {
			for _, one := range listed {
				if at, found := seen[one.GetAgentId()]; found {
					one.LastSeen = timestamppb.New(at.UTC())
				}
			}
		}
	}

	if whole && s.postures != nil {
		if assessed, err := s.postures.Postures(ctx, asked, tenants); err != nil {
			s.logger.Warn("agent_posture_unavailable", slog.String("error", err.Error()))
		} else {
			for _, one := range listed {
				one.Assessment = assessed[one.GetAgentId()]
			}
		}
	}

	if s.reports == nil {
		return
	}
	newest, err := s.reports.Newest(ctx, asked, tenants)
	if err != nil {
		s.logger.Warn("agent_status_unavailable", slog.String("error", err.Error()))
		return
	}
	now := s.now()
	for _, one := range listed {
		held, found := newest[one.GetAgentId()]
		if !found {
			continue
		}
		one.Liveness = held.Liveness(now)
		one.LastReported = timestamppb.New(held.Received.UTC())
		if whole {
			one.Status = held.Status
		}
	}
}
