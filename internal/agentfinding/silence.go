package agentfinding

import (
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentstatus"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// A report as a finding names it: what tells one source from another and when
// the platform received it, never what the report says of the host.
func HeardOf(report *agentv1.Status) *agentv1.Heard {
	return &agentv1.Heard{
		InstallationId: report.GetInstallationId(),
		BootId:         report.GetRun().GetBootId(),
		Sequence:       report.GetSequence(),
		RunStartedAt:   report.GetRun().GetStartedAt(),
		ReportedAt:     report.GetReportedAt(),
		IngestTime:     report.GetReception().GetIngestTime(),
		Gateway:        report.GetReception().GetGateway(),
		Interval:       report.GetInterval(),
		Stopping:       report.GetCondition() == agentv1.Status_CONDITION_STOPPED,
	}
}

// How long an agent whose newest report is this one may stay away before it is
// silent, which is the point its liveness reads silent (ADR 30).
func Threshold(newest *agentv1.Heard) time.Duration {
	return agentstatus.Silence * newest.GetInterval().AsDuration()
}

func SilentFrom(newest *agentv1.Heard) time.Time {
	return newest.GetIngestTime().AsTime().Add(Threshold(newest))
}

func Silence(tenantID, agentID string, newest *agentv1.Heard, decided time.Time) *agentv1.Finding {
	from := timestamppb.New(SilentFrom(newest))
	return &agentv1.Finding{
		SchemaVersion:  SchemaVersion,
		FindingId:      ID(tenantID, agentID, agentv1.Finding_KIND_SILENCE, newest.GetBootId(), strconv.FormatUint(newest.GetSequence(), 10)),
		TenantId:       tenantID,
		AgentId:        agentID,
		Kind:           agentv1.Finding_KIND_SILENCE,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       from,
		LastObservedAt: from,
		Observations:   1,
		DecidedAt:      timestamppb.New(decided.UTC()),
		Reports:        []*agentv1.Heard{proto.Clone(newest).(*agentv1.Heard)},
	}
}

// The decision that ends an open finding, naming what ended it. It never closes
// before it opened: an instant earlier than that is a clock the platform does
// not hold, and the finding says it closed as it opened.
func Closed(open *agentv1.Finding, closure agentv1.Finding_Closure, at, decided time.Time, ending ...*agentv1.Heard) *agentv1.Finding {
	closed := proto.Clone(open).(*agentv1.Finding)
	closed.State = agentv1.Finding_STATE_CLOSED
	closed.Closure = closure
	closed.ClosedAt = timestamppb.New(later(at.UTC(), open.GetOpenedAt().AsTime()))
	closed.DecidedAt = timestamppb.New(decided.UTC())
	kept := min(len(closed.Reports), MaxReports-min(len(ending), MaxReports))
	closed.Reports = closed.Reports[:kept]
	for _, one := range ending[:min(len(ending), MaxReports)] {
		closed.Reports = append(closed.Reports, proto.Clone(one).(*agentv1.Heard))
	}
	return closed
}

func Again(open *agentv1.Finding, decided time.Time) *agentv1.Finding {
	again := proto.Clone(open).(*agentv1.Finding)
	again.DecidedAt = timestamppb.New(decided.UTC())
	return again
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
