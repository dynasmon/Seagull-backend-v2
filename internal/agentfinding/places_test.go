package agentfinding_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
)

func run(installation, boot string, started time.Time) func(sequence uint64, reported time.Time) *agentv1.Heard {
	return func(sequence uint64, reported time.Time) *agentv1.Heard {
		return &agentv1.Heard{
			InstallationId: installation,
			BootId:         boot,
			Sequence:       sequence,
			RunStartedAt:   timestamppb.New(started),
			ReportedAt:     timestamppb.New(reported),
			IngestTime:     timestamppb.New(reported.Add(40 * time.Millisecond)),
			Gateway:        "gateway-1",
			Interval:       durationpb.New(time.Minute),
		}
	}
}

func TestAReportIsPassedWhenAnotherPlaceOfItsInstallationAlreadyHoldsItsSequence(t *testing.T) {
	original := run("installation-a", "boot-a", opened.Add(-time.Hour))
	copied := run("installation-a", "boot-b", opened.Add(-10*time.Minute))
	held := original(100, opened)

	if !agentfinding.Passed(copied(51, opened.Add(time.Minute)), held, time.Time{}) {
		t.Error("a copy counting on from where the original was is not passed")
	}
	if !agentfinding.Passed(copied(100, opened.Add(time.Minute)), held, time.Time{}) {
		t.Error("a sequence heard from two places is not passed")
	}
	if agentfinding.Passed(copied(101, opened.Add(time.Minute)), held, time.Time{}) {
		t.Error("a sequence above every one the other place reported is passed")
	}
}

func TestAReportTheRunAfterItAccountedForIsNotPassed(t *testing.T) {
	before := run("installation-a", "boot-a", opened.Add(-time.Hour))
	after := run("installation-a", "boot-a", opened.Add(time.Minute))
	late := before(100, opened)
	held := after(101, opened.Add(2*time.Minute))

	if agentfinding.Passed(late, held, opened.Add(-30*time.Second)) {
		t.Error("a report written before the next run started was taken for a copy")
	}
	steppedBack := run("installation-a", "boot-b", opened.Add(-time.Minute))
	if agentfinding.Passed(late, steppedBack(101, opened.Add(time.Minute)), opened.Add(time.Second)) {
		t.Error("a report the next run says the run before it outlived was taken for a copy")
	}
	if !agentfinding.Passed(before(100, opened.Add(5*time.Minute)), held, opened) {
		t.Error("a report written after the next run started is accounted for")
	}
	resumed := run("installation-a", "boot-c", opened.Add(3*time.Minute))
	if !agentfinding.Passed(resumed(60, opened.Add(4*time.Minute)), held, opened) {
		t.Error("a run that started after the place holding the sequence is accounted for")
	}
}

func TestTheSameReportSentAgainIsOneReportWhereverItArrived(t *testing.T) {
	sent := run("installation-a", "boot-a", opened.Add(-time.Hour))(41, opened)
	again := proto.Clone(sent).(*agentv1.Heard)
	again.IngestTime, again.Gateway = timestamppb.New(opened.Add(time.Minute)), "gateway-2"
	if !agentfinding.SameReport(sent, again) {
		t.Error("a report sent again through another gateway is another report")
	}
	other := run("installation-a", "boot-a", opened.Add(-time.Hour))(41, opened.Add(time.Second))
	if agentfinding.SameReport(sent, other) {
		t.Error("two reports written under one sequence are one report")
	}
}

func TestAReportIsATurnWhenItIsNewAndWrittenAfterTheOtherInstallationReported(t *testing.T) {
	first := run("installation-a", "boot-a", opened.Add(-time.Hour))
	mine := first(41, opened)
	other := run("installation-b", "boot-b", opened.Add(time.Minute))(1, opened.Add(2*time.Minute))

	if !agentfinding.Turn(first(42, opened.Add(3*time.Minute)), mine, other) {
		t.Error("a new report written while the other installation runs is not a turn")
	}
	if agentfinding.Turn(first(41, opened.Add(3*time.Minute)), mine, other) {
		t.Error("a report its installation had already sent is a turn")
	}
	if agentfinding.Turn(first(42, opened.Add(30*time.Second)), mine, other) {
		t.Error("a report written before the other installation's run began is a turn")
	}
	if agentfinding.Turn(first(43, opened.Add(4*time.Minute)), first(42, opened.Add(3*time.Minute)), other) {
		t.Error("a report is a turn although the other installation wrote nothing since its own newest")
	}
}

func TestACopiedInstallationIsNamedByTheInstallationAndTheFirstSequenceHeardTwice(t *testing.T) {
	original := run("installation-a", "boot-a", opened.Add(-time.Hour))(100, opened)
	copied := run("installation-a", "boot-b", opened.Add(-10*time.Minute))

	first := agentfinding.Copied("default", "web-01", copied(51, opened.Add(time.Minute)), original, opened.Add(2*time.Minute))
	if err := agentfinding.Validate(first); err != nil {
		t.Fatalf("a copied installation the domain made was refused: %v", err)
	}
	arrived := opened.Add(time.Minute + 40*time.Millisecond)
	if first.GetFindingId() != agentfinding.ID("default", "web-01", agentv1.Finding_KIND_COPIED_INSTALLATION, "installation-a", "51") ||
		first.GetKind() != agentv1.Finding_KIND_COPIED_INSTALLATION || first.GetState() != agentv1.Finding_STATE_OPEN ||
		!first.GetOpenedAt().AsTime().Equal(arrived) || !first.GetLastObservedAt().AsTime().Equal(arrived) || first.GetObservations() != 1 ||
		len(first.GetReports()) != 2 || first.GetReports()[0].GetSequence() != 100 || first.GetReports()[1].GetSequence() != 51 {
		t.Errorf("a copied installation was decided as %v", first)
	}
	again := agentfinding.Copied("default", "web-01", copied(51, opened.Add(time.Minute)), original, opened.Add(time.Hour))
	if again.GetFindingId() != first.GetFindingId() || !proto.Equal(again.GetOpenedAt(), first.GetOpenedAt()) {
		t.Error("judging one copy again named another finding or another instant")
	}
	if next := agentfinding.Copied("default", "web-01", copied(52, opened.Add(2*time.Minute)), original, opened); next.GetFindingId() == first.GetFindingId() {
		t.Error("a copy first heard at another sequence is the same finding")
	}
}

func TestASharedIdentityIsNamedByTheTwoInstallationsWhicheverTookTheTurn(t *testing.T) {
	a := run("installation-a", "boot-a", opened.Add(-time.Hour))(42, opened.Add(3*time.Minute))
	b := run("installation-b", "boot-b", opened.Add(time.Minute))(7, opened.Add(2*time.Minute))

	one := agentfinding.Shared("default", "web-01", a, b, opened.Add(4*time.Minute))
	other := agentfinding.Shared("default", "web-01", b, a, opened.Add(4*time.Minute))
	if err := agentfinding.Validate(one); err != nil {
		t.Fatalf("a shared identity the domain made was refused: %v", err)
	}
	if one.GetFindingId() != other.GetFindingId() ||
		one.GetFindingId() != agentfinding.ID("default", "web-01", agentv1.Finding_KIND_SHARED_IDENTITY, "installation-a", "installation-b") {
		t.Error("the two installations name another finding depending on which took the turn")
	}
	if one.GetKind() != agentv1.Finding_KIND_SHARED_IDENTITY || !proto.Equal(one.GetOpenedAt(), a.GetIngestTime()) ||
		one.GetObservations() != 1 || len(one.GetReports()) != 2 || one.GetReports()[1].GetInstallationId() != "installation-a" {
		t.Errorf("a shared identity was decided as %v", one)
	}
}

func TestAnObservationCountsAndNeverMovesTheLastObservedInstantBack(t *testing.T) {
	original := run("installation-a", "boot-a", opened.Add(-time.Hour))
	copied := run("installation-a", "boot-b", opened.Add(-10*time.Minute))
	open := agentfinding.Copied("default", "web-01", copied(51, opened.Add(time.Minute)), original(100, opened), opened.Add(2*time.Minute))

	newer := []*agentv1.Heard{original(103, opened.Add(3*time.Minute)), copied(54, opened.Add(4*time.Minute))}
	observed := agentfinding.Observed(open, opened.Add(4*time.Minute), newer, opened.Add(5*time.Minute))
	if err := agentfinding.Validate(observed); err != nil {
		t.Fatalf("an observed copy was refused: %v", err)
	}
	if observed.GetObservations() != 2 || !observed.GetLastObservedAt().AsTime().Equal(opened.Add(4*time.Minute)) ||
		!proto.Equal(observed.GetOpenedAt(), open.GetOpenedAt()) || observed.GetReports()[1].GetSequence() != 54 ||
		!observed.GetDecidedAt().AsTime().Equal(opened.Add(5*time.Minute)) || open.GetObservations() != 1 {
		t.Errorf("an observation made %v of %v", observed, open)
	}
	earlier := agentfinding.Observed(observed, opened.Add(2*time.Minute), newer, opened.Add(6*time.Minute))
	if earlier.GetObservations() != 3 || !earlier.GetLastObservedAt().AsTime().Equal(opened.Add(4*time.Minute)) {
		t.Errorf("an observation older than the last moved it to %s", earlier.GetLastObservedAt().AsTime())
	}
	crowded := agentfinding.Observed(open, opened.Add(4*time.Minute), append(append(newer, newer...), newer...), opened.Add(5*time.Minute))
	if len(crowded.GetReports()) != agentfinding.MaxReports || agentfinding.Validate(crowded) != nil {
		t.Errorf("an observation naming more places than a finding holds kept %d", len(crowded.GetReports()))
	}
}

func TestASharedIdentityClosedAsOneSourceOpensAgainUnderItsNameAndItsFirstOpening(t *testing.T) {
	a := run("installation-a", "boot-a", opened.Add(-time.Hour))
	b := run("installation-b", "boot-b", opened.Add(time.Minute))(7, opened.Add(2*time.Minute))
	open := agentfinding.Shared("default", "web-01", a(42, opened.Add(3*time.Minute)), b, opened.Add(4*time.Minute))
	ended := agentfinding.Closed(open, agentv1.Finding_CLOSURE_ONE_SOURCE, opened.Add(10*time.Minute), opened.Add(11*time.Minute))

	again := agentfinding.Reopened(ended, opened.Add(time.Hour), []*agentv1.Heard{b, a(90, opened.Add(time.Hour))}, opened.Add(time.Hour+time.Second))
	if err := agentfinding.Validate(again); err != nil {
		t.Fatalf("a shared identity opened again was refused: %v", err)
	}
	if again.GetFindingId() != open.GetFindingId() || again.GetState() != agentv1.Finding_STATE_OPEN ||
		again.GetClosure() != agentv1.Finding_CLOSURE_UNSPECIFIED || again.GetClosedAt() != nil ||
		!proto.Equal(again.GetOpenedAt(), open.GetOpenedAt()) || again.GetObservations() != 2 ||
		!again.GetLastObservedAt().AsTime().Equal(opened.Add(time.Hour)) || ended.GetState() != agentv1.Finding_STATE_CLOSED {
		t.Errorf("a shared identity heard again after it closed was decided as %v", again)
	}
}
