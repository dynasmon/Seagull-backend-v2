package agentupdate_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func verifiedCatalog(t *testing.T, releases ...*updatev1.Release) *agentupdate.Catalog {
	t.Helper()
	owner := newSigner(t)
	trusted := anchored(t, rootOf(1, []signer{owner}, 1, []signer{owner}, 1), owner)
	catalog, err := trusted.Catalog(sign(t, catalogOf(5, releases...), agentupdate.CatalogPayloadType, owner), written)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func reportOf(version string) *agentv1.Status {
	return &agentv1.Status{
		Build: &agentv1.Status_Build{Version: version, Os: "linux", Architecture: "amd64"},
		Compatibility: &agentv1.Status_Compatibility{Updates: &agentv1.Status_Updates{
			Enabled: true, Format: updatev1.Format_FORMAT_DEB, StateGeneration: 1,
		}},
	}
}

func updating(report *agentv1.Status, version string, stage agentv1.Status_Update_Stage, failure agentv1.Status_Update_Failure) *agentv1.Status {
	report.Update = &agentv1.Status_Update{Version: version, Stage: stage, Failure: failure}
	return report
}

func TestWhatAnAgentSaysOfTheReleaseIsWhatARolloutCounts(t *testing.T) {
	catalog := verifiedCatalog(t, releaseOf("v0.2.0", 1), releaseOf("v0.3.0", 2))
	for name, judged := range map[string]struct {
		report *agentv1.Status
		want   agentupdate.Outcome
	}{
		"no report":            {nil, agentupdate.Pending},
		"running the release":  {reportOf("v0.3.0"), agentupdate.Running},
		"not asked yet":        {reportOf("v0.2.0"), agentupdate.Pending},
		"downloading":          {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_DOWNLOADING, 0), agentupdate.Pending},
		"checking it":          {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_CHECKING, 0), agentupdate.Pending},
		"rolled back from it":  {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_ROLLED_BACK, agentv1.Status_Update_FAILURE_UNHEALTHY), agentupdate.Failed},
		"unverified":           {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_FAILED, agentv1.Status_Update_FAILURE_UNVERIFIED), agentupdate.Failed},
		"not installed":        {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_FAILED, agentv1.Status_Update_FAILURE_INSTALLATION), agentupdate.Failed},
		"unhealthy":            {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_FAILED, agentv1.Status_Update_FAILURE_UNHEALTHY), agentupdate.Failed},
		"out of reach":         {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_FAILED, agentv1.Status_Update_FAILURE_UNREACHABLE), agentupdate.Pending},
		"refused it":           {updating(reportOf("v0.2.0"), "v0.3.0", agentv1.Status_Update_STAGE_FAILED, agentv1.Status_Update_FAILURE_REFUSED), agentupdate.Ineligible},
		"failed another":       {updating(reportOf("v0.2.0"), "v0.2.1", agentv1.Status_Update_STAGE_ROLLED_BACK, agentv1.Status_Update_FAILURE_UNHEALTHY), agentupdate.Pending},
		"running, said failed": {updating(reportOf("v0.3.0"), "v0.3.0", agentv1.Status_Update_STAGE_ROLLED_BACK, agentv1.Status_Update_FAILURE_UNHEALTHY), agentupdate.Running},
	} {
		if got := agentupdate.Judge(judged.report, "v0.3.0", catalog); got != judged.want {
			t.Errorf("%s: judged %v, want %v", name, got, judged.want)
		}
	}
}

func TestAnAgentThatCannotTakeTheReleaseIsNotWaitedFor(t *testing.T) {
	recovery := releaseOf("v0.2.1", 3)
	recovery.Replaces = []string{"v0.3.0"}
	floor := releaseOf("v0.4.0", 4)
	floor.Compatibility.MinimumVersion = "v0.3.0"
	moved := releaseOf("v0.5.0", 5)
	moved.Compatibility.StateGeneration = 2
	catalog := verifiedCatalog(t, releaseOf("v0.2.0", 1), releaseOf("v0.3.0", 2), recovery, floor, moved)

	for name, judged := range map[string]struct {
		report *agentv1.Status
		target string
		want   agentupdate.Outcome
	}{
		"a forward release":         {reportOf("v0.2.0"), "v0.3.0", agentupdate.Pending},
		"updates turned off":        {off(reportOf("v0.2.0")), "v0.3.0", agentupdate.Ineligible},
		"another architecture":      {architecture(reportOf("v0.2.0"), "arm64"), "v0.3.0", agentupdate.Ineligible},
		"another format":            {format(reportOf("v0.2.0"), updatev1.Format_FORMAT_UNSPECIFIED), "v0.3.0", agentupdate.Ineligible},
		"newer state":               {generation(reportOf("v0.3.0"), 2), "v0.4.0", agentupdate.Ineligible},
		"state the release keeps":   {generation(reportOf("v0.3.0"), 2), "v0.5.0", agentupdate.Pending},
		"an older release":          {reportOf("v0.3.0"), "v0.2.0", agentupdate.Ineligible},
		"a release replacing it":    {reportOf("v0.3.0"), "v0.2.1", agentupdate.Pending},
		"a recovery for another":    {reportOf("v0.2.0"), "v0.2.1", agentupdate.Pending},
		"below the floor":           {reportOf("v0.2.0"), "v0.4.0", agentupdate.Ineligible},
		"at the floor":              {reportOf("v0.3.0"), "v0.4.0", agentupdate.Pending},
		"nothing to go back to":     {reportOf("v0.1.0"), "v0.3.0", agentupdate.Ineligible},
		"a build of no release":     {reportOf("(devel)"), "v0.3.0", agentupdate.Ineligible},
		"a release not cataloged":   {reportOf("v0.2.0"), "v0.9.0", agentupdate.Ineligible},
		"an agent that predates it": {predates(reportOf("v0.2.0")), "v0.3.0", agentupdate.Pending},
		"one that predates, on arm": {architecture(predates(reportOf("v0.2.0")), "arm64"), "v0.3.0", agentupdate.Ineligible},
		"one that predates, behind": {predates(reportOf("v0.2.0")), "v0.4.0", agentupdate.Ineligible},
	} {
		if got := agentupdate.Judge(judged.report, judged.target, catalog); got != judged.want {
			t.Errorf("%s: judged %v, want %v", name, got, judged.want)
		}
	}
	if got := agentupdate.Judge(off(reportOf("v0.2.0")), "v0.3.0", nil); got != agentupdate.Pending {
		t.Errorf("without a catalog to judge by, an agent was judged %v", got)
	}
}

func off(report *agentv1.Status) *agentv1.Status {
	report.Compatibility.Updates.Enabled = false
	return report
}

func architecture(report *agentv1.Status, named string) *agentv1.Status {
	report.Build.Architecture = named
	return report
}

func format(report *agentv1.Status, format updatev1.Format) *agentv1.Status {
	report.Compatibility.Updates.Format = format
	return report
}

func generation(report *agentv1.Status, kept uint32) *agentv1.Status {
	report.Compatibility.Updates.StateGeneration = kept
	return report
}

func predates(report *agentv1.Status) *agentv1.Status {
	report.Compatibility = nil
	return report
}

func TestATallyCountsEachAgentOnceAndSetsKnownFailuresApart(t *testing.T) {
	tally := agentupdate.Tally{Progress: &updatev1.RolloutProgress{}}
	tally.Count("web-01", agentupdate.Running, false)
	tally.Count("web-02", agentupdate.Failed, false)
	tally.Count("web-03", agentupdate.Failed, true)
	tally.Count("web-04", agentupdate.Ineligible, false)
	tally.Count("web-05", agentupdate.Pending, false)
	want := &updatev1.RolloutProgress{Running: 1, Failed: 1, Acknowledged: 1, Ineligible: 1, Pending: 1}
	if !proto.Equal(tally.Progress, want) || len(tally.Failing) != 1 || tally.Failing[0] != "web-02" {
		t.Fatalf("tallied %v, failing %v", tally.Progress, tally.Failing)
	}
}

func gated(t *testing.T) *updatev1.RolloutRecord {
	t.Helper()
	accepted, err := agentupdate.AcceptRollout(&updatev1.Rollout{
		TenantId: "acme",
		Version:  "v0.3.0",
		Waves: []*updatev1.Wave{
			{AgentIds: []string{"web-01", "web-02"}, Soak: durationpb.New(time.Hour), Running: 2},
			{Percent: 20},
			{Percent: 100},
		},
		Failures: 2,
	}, "ops", written)
	if err != nil {
		t.Fatal(err)
	}
	return accepted.Record
}

func TestAGatePausesARolloutOnceAsManyAgentsFailedAsItAllows(t *testing.T) {
	record := gated(t)
	step, reason := agentupdate.Gate(record, &updatev1.RolloutProgress{Running: 2, Failed: 2}, written.Add(2*time.Hour))
	if step != agentupdate.Pause || reason == "" {
		t.Fatalf("with two failures the gate said %v %q", step, reason)
	}
	if step, _ := agentupdate.Gate(record, &updatev1.RolloutProgress{Running: 2, Failed: 1, Acknowledged: 5}, written.Add(2*time.Hour)); step != agentupdate.Open {
		t.Fatalf("one failure and five known ones held the gate at %v", step)
	}

	paused := agentupdate.Paused(record, reason, written.Add(2*time.Hour))
	if paused.GetState() != updatev1.RolloutRecord_STATE_PAUSED || paused.GetChangedBy() != agentupdate.Platform ||
		paused.GetReason() != reason || paused.GetWave() != 0 || record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE {
		t.Fatalf("paused into %v", paused)
	}
	if step, _ := agentupdate.Gate(paused, &updatev1.RolloutProgress{Failed: 9}, written.Add(3*time.Hour)); step != agentupdate.Hold {
		t.Fatalf("a paused rollout was moved by its gate: %v", step)
	}
}

func TestAWaveOpensTheNextOnceItSoakedAndEnoughAgentsRunTheRelease(t *testing.T) {
	record := gated(t)
	for name, held := range map[string]struct {
		progress *updatev1.RolloutProgress
		at       time.Time
	}{
		"before its soak":      {&updatev1.RolloutProgress{Running: 2}, written.Add(59 * time.Minute)},
		"with too few running": {&updatev1.RolloutProgress{Running: 1, Pending: 1}, written.Add(2 * time.Hour)},
	} {
		if step, _ := agentupdate.Gate(record, held.progress, held.at); step != agentupdate.Hold {
			t.Errorf("%s: the gate said %v", name, step)
		}
	}
	step, reason := agentupdate.Gate(record, &updatev1.RolloutProgress{Running: 2}, written.Add(time.Hour))
	if step != agentupdate.Open {
		t.Fatalf("a wave that soaked with both canaries running was held: %v", step)
	}
	opened := agentupdate.Opened(record, reason, written.Add(time.Hour))
	if opened.GetWave() != 1 || !opened.GetWaveOpenedAt().AsTime().Equal(written.Add(time.Hour)) ||
		opened.GetChangedBy() != agentupdate.Platform || opened.GetState() != updatev1.RolloutRecord_STATE_ACTIVE {
		t.Fatalf("opened into %v", opened)
	}

	if step, _ := agentupdate.Gate(opened, &updatev1.RolloutProgress{Running: 500}, written.Add(48*time.Hour)); step != agentupdate.Hold {
		t.Fatalf("a wave waiting for an operator was opened by its gate: %v", step)
	}
	last := agentupdate.Opened(opened, "", written.Add(49*time.Hour))
	if step, _ := agentupdate.Gate(last, &updatev1.RolloutProgress{Running: 500}, written.Add(50*time.Hour)); step != agentupdate.Hold {
		t.Fatalf("the last wave opened something: %v", step)
	}
	if step, _ := agentupdate.Gate(last, &updatev1.RolloutProgress{Running: 500, Failed: 2}, written.Add(50*time.Hour)); step != agentupdate.Pause {
		t.Fatalf("failures past the last wave did not pause the rollout: %v", step)
	}
}
