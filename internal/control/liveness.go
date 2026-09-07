package control

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// When telemetry from an agent last reached the platform, asked of wherever it
// landed. It is not part of the registry: an agent sends continuously and is
// registered once, so keeping it beside what was decided would put a write on
// the ingest path to record something the stream already says.
type Liveness interface {
	LastSeen(ctx context.Context, agents, tenants []string) (map[string]time.Time, error)
}

// A failure here costs the caller the liveness column and not the answer: the
// registry holds what was decided, and where telemetry landed is a second store
// that may be slower or absent without making an agent unreadable.
func (s *Server) observed(ctx context.Context, listed []*agentv1.Agent, tenants []string) {
	if s.liveness == nil || len(listed) == 0 {
		return
	}

	asked := make([]string, 0, len(listed))
	for _, one := range listed {
		asked = append(asked, one.GetAgentId())
	}

	seen, err := s.liveness.LastSeen(ctx, asked, tenants)
	if err != nil {
		s.logger.Warn("agent_liveness_unavailable", slog.String("error", err.Error()))
		return
	}
	for _, one := range listed {
		if at, found := seen[one.GetAgentId()]; found {
			one.LastSeen = timestamppb.New(at.UTC())
		}
	}
}
