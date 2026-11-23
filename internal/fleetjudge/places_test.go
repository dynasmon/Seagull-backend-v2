package fleetjudge_test

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/fleetjudge"
	"github.com/dynasmon/Seagull-backend-v2/tests/fixtures"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type place struct {
	t            *testing.T
	installation string
	boot         string
	started      time.Time
	previously   time.Time
}

func (p place) written(sequence uint64, written, arrived time.Time) *agentv1.Status {
	report := fixtures.Report{AgentID: "web-01", InstallationID: p.installation, BootID: p.boot, Sequence: sequence, At: written, Interval: time.Minute}.Status()
	report.Origin.TenantId = "default"
	report.Run.StartedAt, report.Run.PreviousSeenAt = timestamppb.New(p.started), nil
	if !p.previously.IsZero() {
		report.Run.PreviousSeenAt = timestamppb.New(p.previously)
	}
	report.Reception = &eventv1.Reception{IngestTime: timestamppb.New(arrived), Gateway: "gateway-1", BatchId: p.boot + "-" + strconv.FormatUint(sequence, 10)}
	return report
}

func (p place) report(sequence uint64, written, arrived time.Time) fleetjudge.Record {
	return encoded(p.t, "web-01", p.written(sequence, written, arrived))
}

func (p place) at(sequence uint64, after time.Duration) fleetjudge.Record {
	return p.report(sequence, start.Add(after-time.Second), start.Add(after))
}

func kinds(decided []*agentv1.Finding, kind agentv1.Finding_Kind) []*agentv1.Finding {
	var found []*agentv1.Finding
	for _, one := range decided {
		if one.GetKind() == kind {
			found = append(found, one)
		}
	}
	return found
}

func twoPlaces(t *testing.T) (*harness, place, place) {
	h := newHarness(t)
	original := place{t: t, installation: "installation-a", boot: "boot-a", started: start.Add(-time.Hour)}
	copied := place{t: t, installation: "installation-a", boot: "boot-b", started: start.Add(-10 * time.Minute)}
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{original.at(100, 0)}
	return h, original, copied
}

func TestAnInstallationReportingFromTwoPlacesIsFoundCopiedOnceAndEveryPassedReportCounted(t *testing.T) {
	h, original, copied := twoPlaces(t)
	h.run()
	h.at(30 * time.Second)

	h.send(h.status.memLog, copied.at(51, time.Minute))
	h.at(time.Minute)
	got := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION)
	if len(got) != 1 {
		t.Fatalf("a copy counting on from the original was decided %d times", len(got))
	}
	first := got[0]
	if err := agentfinding.Validate(first); err != nil || first.GetState() != agentv1.Finding_STATE_OPEN ||
		first.GetFindingId() != agentfinding.ID("default", "web-01", agentv1.Finding_KIND_COPIED_INSTALLATION, "installation-a", "51") ||
		!first.GetOpenedAt().AsTime().Equal(start.Add(time.Minute)) || len(first.GetReports()) != 2 {
		t.Fatalf("the copy was decided as %v (%v)", first, err)
	}
	if open := counted(t, h.exported, `seagull_fleetjudge_open_findings{kind="copied_installation"}`); open != 1 {
		t.Errorf("%v copies are counted open", open)
	}

	h.send(h.status.memLog, original.at(101, 2*time.Minute))
	h.send(h.status.memLog, copied.at(52, 2*time.Minute+30*time.Second))
	h.at(3 * time.Minute)
	if got := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION); len(got) != 1 {
		t.Fatalf("an observation was decided again before a threshold passed: %v", got)
	}
	h.at(6*time.Minute + time.Second)
	got = kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION)
	if len(got) != 2 || got[1].GetFindingId() != first.GetFindingId() || got[1].GetObservations() != 2 ||
		!got[1].GetLastObservedAt().AsTime().Equal(start.Add(2*time.Minute+30*time.Second)) || got[1].GetState() != agentv1.Finding_STATE_OPEN {
		t.Fatalf("a threshold after the copy was observed again the decisions were %v", got)
	}
}

func TestARestartAReportSentAgainAndALateReportOfTheRunBeforeAreOneInstallation(t *testing.T) {
	h := newHarness(t)
	before := place{t: t, installation: "installation-a", boot: "boot-a", started: start.Add(-time.Hour)}
	after := place{t: t, installation: "installation-a", boot: "boot-a", started: start.Add(40 * time.Second), previously: start.Add(20 * time.Second)}
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{before.at(99, 0)}
	h.run()
	h.at(30 * time.Second)

	h.send(h.status.memLog, after.at(101, time.Minute))
	h.send(h.status.memLog, before.report(100, start.Add(10*time.Second), start.Add(90*time.Second)))
	resent := after.written(101, start.Add(59*time.Second), start.Add(105*time.Second))
	resent.Reception.Gateway = "gateway-2"
	h.send(h.status.memLog, encoded(t, "web-01", resent))
	h.send(h.status.memLog, after.at(102, 2*time.Minute))
	h.at(3 * time.Minute)
	h.at(6 * time.Minute)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("one installation restarting was decided as %v", got)
	}
}

func TestAPlaceHeardNoMoreForItsThresholdPassesNothing(t *testing.T) {
	h, _, _ := twoPlaces(t)
	restored := place{t: t, installation: "installation-a", boot: "boot-b", started: start.Add(6 * time.Minute)}
	h.run()
	h.at(30 * time.Second)

	h.send(h.status.memLog, restored.at(51, 6*time.Minute+30*time.Second))
	h.at(7 * time.Minute)
	h.at(13 * time.Minute)
	if got := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION); len(got) != 0 {
		t.Fatalf("an installation heard from one place at a time was decided copied: %v", got)
	}
}

func TestTwoInstallationsReportingInTurnAreFoundSharingOneIdentity(t *testing.T) {
	h := newHarness(t)
	first := place{t: t, installation: "installation-a", boot: "boot-a", started: start.Add(-time.Hour)}
	second := place{t: t, installation: "installation-b", boot: "boot-b", started: start.Add(40 * time.Second)}
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{first.at(41, 0)}
	h.run()
	h.at(30 * time.Second)

	h.send(h.status.memLog, second.at(1, time.Minute))
	h.at(time.Minute)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("an installation heard for the first time was decided as %v", got)
	}
	h.send(h.status.memLog, first.at(42, 90*time.Second))
	h.at(2 * time.Minute)
	got := kinds(h.published.all(), agentv1.Finding_KIND_SHARED_IDENTITY)
	if len(got) != 1 || agentfinding.Validate(got[0]) != nil || got[0].GetState() != agentv1.Finding_STATE_OPEN ||
		got[0].GetFindingId() != agentfinding.ID("default", "web-01", agentv1.Finding_KIND_SHARED_IDENTITY, "installation-a", "installation-b") ||
		!got[0].GetOpenedAt().AsTime().Equal(start.Add(90*time.Second)) {
		t.Fatalf("two installations reporting in turn were decided as %v", got)
	}

	h.send(h.status.memLog, second.at(2, 2*time.Minute+10*time.Second))
	h.at(6*time.Minute + 5*time.Second)
	got = kinds(h.published.all(), agentv1.Finding_KIND_SHARED_IDENTITY)
	if len(got) != 2 || got[1].GetObservations() != 2 || got[1].GetFindingId() != got[0].GetFindingId() || got[1].GetState() != agentv1.Finding_STATE_OPEN {
		t.Fatalf("the next turn was decided as %v", got)
	}
}

func TestTheLateReportsOfAReplacedInstallationTakeNoTurn(t *testing.T) {
	h := newHarness(t)
	replaced := place{t: t, installation: "installation-a", boot: "boot-a", started: start.Add(-time.Hour)}
	replacing := place{t: t, installation: "installation-b", boot: "boot-a", started: start.Add(40 * time.Second)}
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{replaced.at(41, 0)}
	h.run()
	h.at(30 * time.Second)

	h.send(h.status.memLog, replacing.at(1, time.Minute))
	h.send(h.status.memLog, replaced.report(42, start.Add(30*time.Second), start.Add(90*time.Second)))
	h.send(h.status.memLog, replacing.at(2, 2*time.Minute))
	h.send(h.status.memLog, replacing.at(3, 3*time.Minute))
	h.at(4 * time.Minute)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("an installation replacing another was decided as %v", got)
	}
}

func TestACopyClosesAsOneSourceOnceOnlyOnePlaceWasHeardForAThresholdOfListening(t *testing.T) {
	h, original, copied := twoPlaces(t)
	h.run()
	h.at(30 * time.Second)
	h.send(h.status.memLog, copied.at(51, time.Minute))
	h.at(time.Minute)

	for minute := 2; minute <= 11; minute++ {
		h.send(h.status.memLog, original.at(uint64(99+minute), time.Duration(minute)*time.Minute))
		switch minute {
		case 3:
			h.status.lag(1)
		case 6:
			h.status.lag(0)
		}
		h.at(time.Duration(minute)*time.Minute + 30*time.Second)
		if got := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION); minute == 10 && len(got) != 1 {
			t.Fatalf("a copy closed before a whole threshold of listening followed the break: %v", got)
		}
	}
	got := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION)
	if len(got) != 2 {
		t.Fatalf("the copy was decided %d times once only the original was heard", len(got))
	}
	closed := got[1]
	if err := agentfinding.Validate(closed); err != nil || closed.GetClosure() != agentv1.Finding_CLOSURE_ONE_SOURCE ||
		!closed.GetClosedAt().AsTime().Equal(start.Add(6*time.Minute)) || closed.GetFindingId() != got[0].GetFindingId() {
		t.Fatalf("the copy closed as %v (%v)", closed, err)
	}
	h.send(h.status.memLog, original.at(110, 12*time.Minute))
	h.at(12*time.Minute + 30*time.Second)
	if again := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION); len(again) != 2 {
		t.Fatalf("the original reporting on alone was decided as %v", again)
	}
}

func TestASharedIdentityHeardAgainAfterItClosedOpensAgainUnderItsName(t *testing.T) {
	h := newHarness(t)
	first := place{t: t, installation: "installation-a", boot: "boot-a", started: start.Add(-time.Hour)}
	second := place{t: t, installation: "installation-b", boot: "boot-b", started: start.Add(40 * time.Second)}
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.status.replay = []fleetjudge.Record{first.at(41, 0)}
	h.run()
	h.at(30 * time.Second)
	h.send(h.status.memLog, second.at(1, time.Minute))
	h.send(h.status.memLog, first.at(42, 90*time.Second))
	h.at(2 * time.Minute)
	for minute := 3; minute <= 8; minute++ {
		h.send(h.status.memLog, first.at(uint64(40+minute), time.Duration(minute)*time.Minute))
		h.at(time.Duration(minute)*time.Minute + 30*time.Second)
	}
	got := kinds(h.published.all(), agentv1.Finding_KIND_SHARED_IDENTITY)
	if len(got) != 2 || got[1].GetClosure() != agentv1.Finding_CLOSURE_ONE_SOURCE || !got[1].GetClosedAt().AsTime().Equal(start.Add(6*time.Minute)) {
		t.Fatalf("the shared identity was decided as %v, want it closed once only one installation was heard", got)
	}

	h.send(h.status.memLog, second.at(2, 9*time.Minute))
	h.send(h.status.memLog, first.at(49, 9*time.Minute+30*time.Second))
	h.at(10 * time.Minute)
	got = kinds(h.published.all(), agentv1.Finding_KIND_SHARED_IDENTITY)
	if len(got) != 3 || got[2].GetFindingId() != got[0].GetFindingId() || got[2].GetState() != agentv1.Finding_STATE_OPEN ||
		!proto.Equal(got[2].GetOpenedAt(), got[0].GetOpenedAt()) || got[2].GetObservations() != got[1].GetObservations()+1 {
		t.Fatalf("the two installations taking turns again were decided as %v", got)
	}
}

func TestACopyClosesWhenTheRegistryStopsAdmittingTheAgent(t *testing.T) {
	h, _, copied := twoPlaces(t)
	h.run()
	h.at(30 * time.Second)
	h.send(h.status.memLog, copied.at(51, time.Minute))
	h.at(time.Minute)

	h.send(h.admissions, admitted(t, "web-01", agentv1.State_STATE_REVOKED, start.Add(90*time.Second)))
	h.at(2 * time.Minute)
	got := kinds(h.published.all(), agentv1.Finding_KIND_COPIED_INSTALLATION)
	if len(got) != 2 || got[1].GetClosure() != agentv1.Finding_CLOSURE_NOT_ADMITTED || !got[1].GetClosedAt().AsTime().Equal(start.Add(90*time.Second)) {
		t.Fatalf("revoking a copied agent decided %v", got)
	}
}

func TestNothingIsFoundCopiedFromReportsReadBack(t *testing.T) {
	h, _, copied := twoPlaces(t)
	h.status.replay = append(h.status.replay, copied.at(51, time.Minute), copied.at(52, 2*time.Minute))
	h.clock.set(start.Add(3 * time.Minute))
	h.run()
	h.at(3 * time.Minute)
	h.at(4 * time.Minute)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("reports read back at a start were decided as %v", got)
	}
}

func TestARestartKeepsTheCopyItLeftOpenAndCountsWhatArrivedMeanwhileOnce(t *testing.T) {
	h, original, copied := twoPlaces(t)
	left := agentfinding.Copied("default", "web-01", agentfinding.HeardOf(copied.written(51, start.Add(59*time.Second), start.Add(time.Minute))),
		agentfinding.HeardOf(original.written(100, start.Add(-time.Second), start)), start.Add(time.Minute))
	left = agentfinding.Observed(left, start.Add(2*time.Minute), left.GetReports(), start.Add(2*time.Minute))
	h.findings.replay = []fleetjudge.Record{remembered(t, left)}
	h.status.replay = append(h.status.replay, copied.at(51, time.Minute), copied.at(52, 2*time.Minute),
		original.at(101, 2*time.Minute+30*time.Second), copied.at(53, 3*time.Minute))
	h.clock.set(start.Add(4 * time.Minute))
	h.run()
	h.at(4 * time.Minute)

	h.send(h.status.memLog, copied.at(54, 5*time.Minute))
	h.at(8 * time.Minute)
	got := h.published.all()
	if len(got) != 1 || got[0].GetFindingId() != left.GetFindingId() || got[0].GetObservations() != 4 ||
		!got[0].GetLastObservedAt().AsTime().Equal(start.Add(5*time.Minute)) || got[0].GetState() != agentv1.Finding_STATE_OPEN {
		t.Fatalf("after a restart the judge decided %v, want the copy it left open observed twice more", got)
	}
	if open := counted(t, h.exported, `seagull_fleetjudge_open_findings{kind="copied_installation"}`); open != 1 {
		t.Errorf("%v copies are counted open after a restart", open)
	}
}

func TestARestartClosesACopyItLeftOpenForAnAgentNoLongerAdmitted(t *testing.T) {
	h, original, copied := twoPlaces(t)
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_DISABLED, start.Add(2*time.Minute))}
	left := agentfinding.Copied("default", "web-01", agentfinding.HeardOf(copied.written(51, start.Add(59*time.Second), start.Add(time.Minute))),
		agentfinding.HeardOf(original.written(100, start.Add(-time.Second), start)), start.Add(time.Minute))
	h.findings.replay = []fleetjudge.Record{remembered(t, left)}
	h.clock.set(start.Add(4 * time.Minute))
	h.run()
	h.quietly(4 * time.Minute)

	got := h.published.all()
	if len(got) != 1 || got[0].GetClosure() != agentv1.Finding_CLOSURE_NOT_ADMITTED || !got[0].GetClosedAt().AsTime().Equal(start.Add(2*time.Minute)) {
		t.Fatalf("a copy left open for an agent since disabled was decided as %v", got)
	}
}

func TestAReportOfItsOwnRunArrivingAfterALaterOneIsNoCopy(t *testing.T) {
	h, original, _ := twoPlaces(t)
	h.run()
	h.at(30 * time.Second)
	h.send(h.status.memLog, original.at(102, 2*time.Minute))
	h.send(h.status.memLog, original.report(101, start.Add(time.Minute), start.Add(150*time.Second)))
	h.at(3 * time.Minute)
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("a report its own run had replaced, arriving late, was decided as %v", got)
	}
}

func TestAnAgentHoldsAtMostFourOpenFindingsOfAKindWhateverItsKeyHolderSends(t *testing.T) {
	for kind, episode := range map[agentv1.Finding_Kind]func(t *testing.T, step string, at time.Duration) []fleetjudge.Record{
		agentv1.Finding_KIND_COPIED_INSTALLATION: func(t *testing.T, step string, at time.Duration) []fleetjudge.Record {
			original := place{t: t, installation: "installation-" + step, boot: "boot-a" + step, started: start.Add(at - time.Hour)}
			copied := place{t: t, installation: "installation-" + step, boot: "boot-b" + step, started: start.Add(at - 5*time.Second)}
			return []fleetjudge.Record{original.at(100, at), copied.at(50, at+10*time.Second)}
		},
		agentv1.Finding_KIND_SHARED_IDENTITY: func(t *testing.T, step string, at time.Duration) []fleetjudge.Record {
			first := place{t: t, installation: "installation-a" + step, boot: "boot-a" + step, started: start.Add(at - 10*time.Second)}
			second := place{t: t, installation: "installation-b" + step, boot: "boot-b" + step, started: start.Add(at - 10*time.Second)}
			return []fleetjudge.Record{first.at(1, at), second.at(1, at+10*time.Second), first.at(2, at+20*time.Second)}
		},
	} {
		t.Run(agentfinding.KindName(kind), func(t *testing.T) {
			h := newHarness(t)
			h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
			h.run()
			for step := range 6 {
				at := 30*time.Second + time.Duration(step)*6*time.Minute
				h.send(h.status.memLog, episode(t, strconv.Itoa(step), at)...)
				h.at(at + 30*time.Second)
			}
			opened := map[string]bool{}
			for _, one := range kinds(h.published.all(), kind) {
				opened[one.GetFindingId()] = one.GetState() == agentv1.Finding_STATE_OPEN
			}
			if len(opened) != 4 {
				t.Fatalf("six episodes of one agent, each in places heard no more, opened %d findings, want four", len(opened))
			}
			name := agentfinding.KindName(kind)
			if open := counted(t, h.exported, `seagull_fleetjudge_open_findings{kind="`+name+`"}`); open != 4 {
				t.Errorf("%v findings are held open", open)
			}
			if unopened := counted(t, h.exported, `seagull_fleetjudge_findings_not_opened_total{kind="`+name+`"}`); unopened != 2 {
				t.Errorf("%v episodes are counted as not opened, want two", unopened)
			}
		})
	}
}

func TestAFindingThatClosedLeavesRoomForTheNextEpisodeOfItsAgent(t *testing.T) {
	h := newHarness(t)
	h.admissions.replay = []fleetjudge.Record{admitted(t, "web-01", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour))}
	h.run()
	for step := range 6 {
		at := 30*time.Second + time.Duration(step)*15*time.Minute
		first := place{t: t, installation: "installation-a" + strconv.Itoa(step), boot: "boot-a" + strconv.Itoa(step), started: start.Add(at - 10*time.Second)}
		second := place{t: t, installation: "installation-b" + strconv.Itoa(step), boot: "boot-b" + strconv.Itoa(step), started: start.Add(at - 10*time.Second)}
		h.send(h.status.memLog, first.at(1, at), second.at(1, at+10*time.Second), first.at(2, at+20*time.Second))
		for minute := range 8 {
			h.at(at + time.Duration(minute)*time.Minute + 30*time.Second)
			h.send(h.status.memLog, second.at(uint64(minute+2), at+time.Duration(minute+1)*time.Minute))
		}
	}
	closed := map[string]bool{}
	for _, one := range kinds(h.published.all(), agentv1.Finding_KIND_SHARED_IDENTITY) {
		closed[one.GetFindingId()] = one.GetClosure() == agentv1.Finding_CLOSURE_ONE_SOURCE
	}
	if len(closed) != 6 || slices.Contains(slices.Collect(maps.Values(closed)), false) {
		t.Fatalf("six shared identities each ending as one source were decided as %v", closed)
	}
	if unopened := counted(t, h.exported, `seagull_fleetjudge_findings_not_opened_total{kind="shared_identity"}`); unopened != 0 {
		t.Errorf("%v episodes are counted as not opened while every finding before them had closed", unopened)
	}
}

func TestEveryAgentKeepsItsPlacesApart(t *testing.T) {
	h, original, copied := twoPlaces(t)
	h.admissions.replay = append(h.admissions.replay, admitted(t, "web-02", agentv1.State_STATE_ACTIVE, start.Add(-time.Hour)))
	other := copied.written(51, start.Add(59*time.Second), start.Add(time.Minute))
	other.Origin.AgentId = "web-02"
	h.run()
	h.at(30 * time.Second)
	h.send(h.status.memLog, encoded(t, "web-02", other))
	h.send(h.status.memLog, original.at(101, 2*time.Minute))
	h.judge.Sweep(context.Background())
	if got := h.published.all(); len(got) != 0 {
		t.Fatalf("one installation reported by two agents was decided as %v", got)
	}
}
