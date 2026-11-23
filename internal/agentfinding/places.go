package agentfinding

import (
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

// An installation runs once at a time and never writes a sequence twice, so a
// report is passed when another place of its installation already holds its
// sequence. A report of an earlier run is the exception, when it was written
// before the run holding the sequence began, or before the moment that run says
// the one before it was last seen: it is late, not copied.
func Passed(report, held *agentv1.Heard, previously time.Time) bool {
	return report.GetSequence() <= held.GetSequence() && !accountedFor(report, held, previously)
}

func accountedFor(late, held *agentv1.Heard, previously time.Time) bool {
	began := held.GetRunStartedAt().AsTime()
	return late.GetRunStartedAt().AsTime().Before(began) && !late.GetReportedAt().AsTime().After(later(began, previously))
}

func SameReport(a, b *agentv1.Heard) bool {
	return a.GetInstallationId() == b.GetInstallationId() && a.GetBootId() == b.GetBootId() &&
		a.GetSequence() == b.GetSequence() && a.GetReportedAt().AsTime().Equal(b.GetReportedAt().AsTime())
}

// An installation that replaced another is the only one heard from then on, so
// a report is a turn when it is new for its installation, the other installation
// wrote its newest after this one's, and it was written after the other's run
// began. Each is judged by when it was written, so a report the replaced one
// sent before it stopped and that arrived late takes no turn.
func Turn(report, mine, other *agentv1.Heard) bool {
	return report.GetSequence() > mine.GetSequence() &&
		other.GetReportedAt().AsTime().After(mine.GetReportedAt().AsTime()) &&
		report.GetReportedAt().AsTime().After(other.GetRunStartedAt().AsTime())
}

func Copied(tenantID, agentID string, first, other *agentv1.Heard, decided time.Time) *agentv1.Finding {
	return opening(agentv1.Finding_KIND_COPIED_INSTALLATION, tenantID, agentID, first, other, decided,
		first.GetInstallationId(), strconv.FormatUint(first.GetSequence(), 10))
}

func Shared(tenantID, agentID string, turn, other *agentv1.Heard, decided time.Time) *agentv1.Finding {
	pair := []string{turn.GetInstallationId(), other.GetInstallationId()}
	slices.Sort(pair)
	return opening(agentv1.Finding_KIND_SHARED_IDENTITY, tenantID, agentID, turn, other, decided, pair...)
}

func opening(kind agentv1.Finding_Kind, tenantID, agentID string, observed, other *agentv1.Heard, decided time.Time, episode ...string) *agentv1.Finding {
	at := observed.GetIngestTime().AsTime()
	return &agentv1.Finding{
		SchemaVersion:  SchemaVersion,
		FindingId:      ID(tenantID, agentID, kind, episode...),
		TenantId:       tenantID,
		AgentId:        agentID,
		Kind:           kind,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(at),
		LastObservedAt: timestamppb.New(at),
		Observations:   1,
		DecidedAt:      timestamppb.New(decided.UTC()),
		Reports:        clones([]*agentv1.Heard{other, observed}),
	}
}

func Observed(open *agentv1.Finding, at time.Time, reports []*agentv1.Heard, decided time.Time) *agentv1.Finding {
	observed := proto.Clone(open).(*agentv1.Finding)
	observed.Observations++
	observed.LastObservedAt = timestamppb.New(later(at.UTC(), open.GetLastObservedAt().AsTime()))
	observed.DecidedAt = timestamppb.New(decided.UTC())
	observed.Reports = clones(reports[:min(len(reports), MaxReports)])
	return observed
}

func Reopened(closed *agentv1.Finding, at time.Time, reports []*agentv1.Heard, decided time.Time) *agentv1.Finding {
	again := Observed(closed, at, reports, decided)
	again.State = agentv1.Finding_STATE_OPEN
	again.Closure = agentv1.Finding_CLOSURE_UNSPECIFIED
	again.ClosedAt = nil
	return again
}

func clones(reports []*agentv1.Heard) []*agentv1.Heard {
	cloned := make([]*agentv1.Heard, 0, len(reports))
	for _, one := range reports {
		cloned = append(cloned, proto.Clone(one).(*agentv1.Heard))
	}
	return cloned
}
