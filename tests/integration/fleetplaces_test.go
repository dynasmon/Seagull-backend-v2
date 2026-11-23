//go:build integration

package integration_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

func (j *judged) reportFrom(installation, boot string, started time.Time, sequence uint64, arrived time.Time) {
	j.t.Helper()
	report := fixtures.Report{AgentID: j.agentID, InstallationID: installation, BootID: boot, Sequence: sequence, At: arrived.Add(-time.Second), Interval: time.Minute}.Status()
	report.Origin.TenantId = "default"
	report.Run.StartedAt, report.Run.PreviousSeenAt = timestamppb.New(started), nil
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-integration", BatchId: boot + "-" + strconv.FormatUint(sequence, 10)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := j.status.PublishStatus(ctx, []*agentv1.Status{report}); err != nil {
		j.t.Fatalf("publish a report: %v", err)
	}
}

func TestAnInstallationReportingFromTwoPlacesIsFoundCopiedOnceAcrossARestartOfTheJudge(t *testing.T) {
	j := judging(t)
	j.silentAt = j.clock.now()
	original := func(sequence uint64, after time.Duration) {
		j.reportFrom("installation-it-a", "boot-a", j.silentAt.Add(-time.Hour), sequence, j.silentAt.Add(after))
	}
	copied := func(sequence uint64, after time.Duration) {
		j.reportFrom("installation-it-a", "boot-b", j.silentAt.Add(-10*time.Minute), sequence, j.silentAt.Add(after))
	}
	original(100, 0)
	j.start()
	j.at(30*time.Second, true)

	copied(51, time.Minute)
	j.caughtUp("status")
	j.at(time.Minute, true)
	decided := j.decisions()
	want := agentfinding.ID("default", j.agentID, agentv1.Finding_KIND_COPIED_INSTALLATION, "installation-it-a", "51")
	if len(decided) != 1 || decided[0].GetFindingId() != want || decided[0].GetState() != agentv1.Finding_STATE_OPEN ||
		!decided[0].GetOpenedAt().AsTime().Equal(j.silentAt.Add(time.Minute)) {
		t.Fatalf("the backbone holds %v, want one open copy of installation-it-a first heard at 51", decided)
	}

	original(101, 2*time.Minute)
	copied(52, 2*time.Minute+30*time.Second)
	j.caughtUp("status")
	j.exported = metrics.New("integration-fleet-judge-restarted")
	j.start()
	j.at(3*time.Minute, true)
	original(102, 3*time.Minute+30*time.Second)
	copied(53, 3*time.Minute+30*time.Second)
	j.caughtUp("status")
	j.at(8*time.Minute, true)
	decided = j.decisions()
	if len(decided) < 2 {
		t.Fatalf("the backbone holds %v, want the copy decided again once it was observed", decided)
	}
	for _, one := range decided {
		if one.GetFindingId() != want || one.GetKind() != agentv1.Finding_KIND_COPIED_INSTALLATION {
			t.Fatalf("a judge started while the copy was open decided %v", one)
		}
	}
	if newest := decided[len(decided)-1]; newest.GetObservations() != 3 || newest.GetState() != agentv1.Finding_STATE_OPEN {
		t.Fatalf("the newest decision is %v, want the copy open and observed three times", newest)
	}
}
