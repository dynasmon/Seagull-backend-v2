package agentupdate_test

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

func canaryThenEveryone(canaries ...string) *updatev1.Rollout {
	return &updatev1.Rollout{
		TenantId: "acme",
		Version:  "v0.3.0",
		Waves: []*updatev1.Wave{
			{AgentIds: canaries, Soak: durationpb.New(time.Hour), Running: uint32(len(canaries))},
			{Percent: 10, Soak: durationpb.New(6 * time.Hour), Running: 50},
			{Percent: 100},
		},
		Failures: 1,
		Note:     "move acme to v0.3.0",
	}
}

func TestARolloutIsTakenActiveAtItsFirstWaveUnderAnIdentifierThePlatformDraws(t *testing.T) {
	asked := canaryThenEveryone("web-01", "web-02")
	accepted, err := agentupdate.AcceptRollout(asked, "ops", written)
	if err != nil {
		t.Fatalf("the rollout was refused: %v", err)
	}
	record := accepted.Record
	if !agentupdate.ValidRolloutID(record.GetRolloutId()) || record.GetRolloutId()[14] != '4' ||
		!strings.ContainsAny(record.GetRolloutId()[19:20], "89ab") {
		t.Fatalf("the rollout is named %q, which is no random UUID", record.GetRolloutId())
	}
	if record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE || record.GetWave() != 0 ||
		!record.GetWaveOpenedAt().AsTime().Equal(written) || record.GetCreatedBy() != "ops" || record.GetChangedBy() != "ops" ||
		!record.GetCreatedAt().AsTime().Equal(written) || record.GetReason() != "move acme to v0.3.0" {
		t.Fatalf("recorded %v", record)
	}

	asked.Waves[0].AgentIds[0] = "changed-later"
	if accepted.Rollout().GetWaves()[0].GetAgentIds()[0] != "web-01" {
		t.Fatal("the rollout taken shares its waves with what was asked")
	}

	again, err := agentupdate.AcceptRollout(canaryThenEveryone("web-01"), "ops", written)
	if err != nil || again.ID() == accepted.ID() {
		t.Fatalf("two rollouts were both named %s (%v)", again.ID(), err)
	}
}

func TestARolloutStatesItsAgentsAndItsWavesWithinTheirBounds(t *testing.T) {
	soak := durationpb.New(time.Hour)
	for name, change := range map[string]func(*updatev1.Rollout){
		"no tenant":                       func(r *updatev1.Rollout) { r.TenantId = "" },
		"an unusable tenant":              func(r *updatev1.Rollout) { r.TenantId = "a b" },
		"no version":                      func(r *updatev1.Rollout) { r.Version = "" },
		"a version without its v":         func(r *updatev1.Rollout) { r.Version = "0.3.0" },
		"no failure pauses it":            func(r *updatev1.Rollout) { r.Failures = 0 },
		"more failures than agents":       func(r *updatev1.Rollout) { r.Failures = agentupdate.MaxFailures + 1 },
		"a long note":                     func(r *updatev1.Rollout) { r.Note = strings.Repeat("n", 513) },
		"an agent named twice":            func(r *updatev1.Rollout) { r.AgentIds = []string{"web-01", "web-02", "web-01"} },
		"an unusable agent":               func(r *updatev1.Rollout) { r.AgentIds = []string{"web 01"} },
		"a canary outside the rollout":    func(r *updatev1.Rollout) { r.AgentIds = []string{"web-02"} },
		"too many agents":                 func(r *updatev1.Rollout) { r.AgentIds = agents(agentupdate.MaxRolloutAgents + 1) },
		"no wave":                         func(r *updatev1.Rollout) { r.Waves = nil },
		"too many waves":                  func(r *updatev1.Rollout) { r.Waves = shares(agentupdate.MaxWaves + 1) },
		"a wave naming and sharing":       func(r *updatev1.Rollout) { r.Waves[0].Percent = 5 },
		"a wave doing neither":            func(r *updatev1.Rollout) { r.Waves[0].AgentIds = nil },
		"a canary named twice":            func(r *updatev1.Rollout) { r.Waves[0].AgentIds = []string{"web-01", "web-01"} },
		"too many canaries":               func(r *updatev1.Rollout) { r.Waves[0].AgentIds = agents(agentupdate.MaxCanaryAgents + 1) },
		"a share that does not grow":      func(r *updatev1.Rollout) { r.Waves[1].Percent = 100 },
		"a share over everyone":           func(r *updatev1.Rollout) { r.Waves[2].Percent = 101 },
		"a last wave short of everyone":   func(r *updatev1.Rollout) { r.Waves[2].Percent = 90 },
		"a last wave that soaks":          func(r *updatev1.Rollout) { r.Waves[2].Soak = soak },
		"a last wave that requires":       func(r *updatev1.Rollout) { r.Waves[2].Running = 1 },
		"a soak requiring nobody":         func(r *updatev1.Rollout) { r.Waves[1].Running = 0 },
		"an operator's wave requiring":    func(r *updatev1.Rollout) { r.Waves[1].Soak = nil },
		"a soak shorter than a minute":    func(r *updatev1.Rollout) { r.Waves[1].Soak = durationpb.New(59 * time.Second) },
		"a soak longer than thirty days":  func(r *updatev1.Rollout) { r.Waves[1].Soak = durationpb.New(31 * 24 * time.Hour) },
		"a soak that is no duration":      func(r *updatev1.Rollout) { r.Waves[1].Soak = &durationpb.Duration{Seconds: 3600, Nanos: -1} },
		"more running than ever required": func(r *updatev1.Rollout) { r.Waves[1].Running = agentupdate.MaxRunning + 1 },
	} {
		asked := canaryThenEveryone("web-01")
		change(asked)
		if _, err := agentupdate.AcceptRollout(asked, "ops", written); !errors.Is(err, agentupdate.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if _, err := agentupdate.AcceptRollout(canaryThenEveryone("web-01"), "", written); !errors.Is(err, agentupdate.ErrNoActor) {
		t.Errorf("a rollout nobody made was taken: %v", err)
	}

	everyone := &updatev1.Rollout{TenantId: "acme", Version: "v0.3.0", Waves: []*updatev1.Wave{{Percent: 100}}, Failures: 3}
	if _, err := agentupdate.AcceptRollout(everyone, "ops", written); err != nil {
		t.Errorf("a rollout of one wave to everyone was refused: %v", err)
	}
	waiting := canaryThenEveryone("web-01")
	waiting.Waves[0].Soak, waiting.Waves[0].Running = nil, 0
	if _, err := agentupdate.AcceptRollout(waiting, "ops", written); err != nil {
		t.Errorf("a canary waiting for an operator was refused: %v", err)
	}
}

func agents(count int) []string {
	named := make([]string, count)
	for index := range named {
		named[index] = fmt.Sprintf("web-%05d", index)
	}
	return named
}

func shares(count int) []*updatev1.Wave {
	waves := make([]*updatev1.Wave, count)
	for index := range waves {
		waves[index] = &updatev1.Wave{Percent: uint32(index + 1)}
	}
	waves[count-1].Percent = 100
	return waves
}

func TestAnAgentsPlaceIsTheOneTheContractStates(t *testing.T) {
	for _, agentID := range []string{"web-01", "web-02", "db-01"} {
		rolloutID := "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b"
		sum := sha256.Sum256([]byte(rolloutID + "\x00" + agentID))
		if want := uint32(binary.BigEndian.Uint64(sum[:8]) % 10000); agentupdate.Place(rolloutID, agentID) != want {
			t.Errorf("%s stands at %d, and the contract places it at %d", agentID, agentupdate.Place(rolloutID, agentID), want)
		}
	}
}

func TestAWaveReachesTheShareItOpensAndKeepsWhatEarlierWavesReached(t *testing.T) {
	rollout := &updatev1.Rollout{Waves: []*updatev1.Wave{
		{AgentIds: []string{"canary"}},
		{Percent: 10},
		{Percent: 50},
		{Percent: 100},
	}}
	const rolloutID = "0b1e8f5c-2d4a-4c3e-8f7a-6b5c4d3e2f10"
	fleet := agents(20000)

	reached := make([]int, len(rollout.Waves))
	for _, id := range fleet {
		before := false
		for wave := range rollout.Waves {
			now := agentupdate.Reaches(rolloutID, rollout, uint32(wave), id)
			if before && !now {
				t.Fatalf("wave %d no longer reaches %s, which an earlier wave reached", wave, id)
			}
			if now {
				reached[wave]++
			}
			before = now
		}
	}
	if reached[0] != 0 || reached[3] != len(fleet) {
		t.Fatalf("the waves reached %v of %d agents", reached, len(fleet))
	}
	for wave, share := range map[int]float64{1: 0.10, 2: 0.50} {
		if got := float64(reached[wave]) / float64(len(fleet)); got < share-0.02 || got > share+0.02 {
			t.Errorf("wave %d reached %.3f of the agents, and opens %.2f", wave, got, share)
		}
	}
	for wave := range rollout.Waves {
		if !agentupdate.Reaches(rolloutID, rollout, uint32(wave), "canary") {
			t.Errorf("wave %d does not reach the canary its first wave named", wave)
		}
	}
	if agentupdate.Reaches(rolloutID, rollout, 99, "web-00001") != true {
		t.Error("a wave past the last reaches less than the last")
	}
}

func TestEachRolloutReachesTheAgentsOfATenantInAnOrderOfItsOwn(t *testing.T) {
	rollout := &updatev1.Rollout{Waves: []*updatev1.Wave{{Percent: 10}, {Percent: 100}}}
	fleet := agents(2000)
	first, second := "a5d3c2b1-0f9e-4d8c-b7a6-958473625140", "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
	shared := 0
	for _, id := range fleet {
		if agentupdate.Reaches(first, rollout, 0, id) && agentupdate.Reaches(second, rollout, 0, id) {
			shared++
		}
	}
	if shared > len(fleet)/20 {
		t.Fatalf("two rollouts first reached the same %d of %d agents", shared, len(fleet))
	}
}

func TestOnlyAnActiveRolloutAsksAnAgentItReachesToRunItsRelease(t *testing.T) {
	accepted, err := agentupdate.AcceptRollout(canaryThenEveryone("web-01"), "ops", written)
	if err != nil {
		t.Fatal(err)
	}
	record := accepted.Record
	if got := agentupdate.Offered(record, true, "web-01"); got != "v0.3.0" {
		t.Fatalf("the canary is offered %q", got)
	}
	if got := agentupdate.Offered(record, false, "web-01"); got != "" {
		t.Fatalf("an agent outside the rollout is offered %q", got)
	}
	for _, state := range []updatev1.RolloutRecord_State{
		updatev1.RolloutRecord_STATE_PAUSED, updatev1.RolloutRecord_STATE_ABORTED, updatev1.RolloutRecord_STATE_SUPERSEDED,
	} {
		record.State = state
		if got := agentupdate.Offered(record, true, "web-01"); got != "" {
			t.Errorf("a %s rollout offers the canary %q", agentupdate.StateName(state), got)
		}
	}
	if agentupdate.Offered(nil, true, "web-01") != "" {
		t.Error("no rollout offers something")
	}
}

func TestAChangeAppliesOnlyWhereTheRolloutStands(t *testing.T) {
	accepted, err := agentupdate.AcceptRollout(canaryThenEveryone("web-01"), "ops", written)
	if err != nil {
		t.Fatal(err)
	}
	change := func(action updatev1.RolloutChange_Action) agentupdate.AcceptedChange {
		t.Helper()
		accepted, err := agentupdate.AcceptChange(&updatev1.RolloutChange{
			TenantId: "acme", RolloutId: accepted.ID(), Action: action, Note: "looked at it",
		}, "lead", written.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return accepted
	}

	active := accepted.Record
	paused, acknowledge, err := change(updatev1.RolloutChange_ACTION_PAUSE).Apply(active)
	if err != nil || acknowledge || paused.GetState() != updatev1.RolloutRecord_STATE_PAUSED ||
		paused.GetChangedBy() != "lead" || paused.GetReason() != "looked at it" || active.GetState() != updatev1.RolloutRecord_STATE_ACTIVE {
		t.Fatalf("paused into %v, %v (%v)", paused, acknowledge, err)
	}
	resumed, acknowledge, err := change(updatev1.RolloutChange_ACTION_RESUME).Apply(paused)
	if err != nil || !acknowledge || resumed.GetState() != updatev1.RolloutRecord_STATE_ACTIVE {
		t.Fatalf("resumed into %v, %v (%v)", resumed, acknowledge, err)
	}
	advanced, _, err := change(updatev1.RolloutChange_ACTION_ADVANCE).Apply(resumed)
	if err != nil || advanced.GetWave() != 1 || !advanced.GetWaveOpenedAt().AsTime().Equal(written.Add(time.Hour)) {
		t.Fatalf("advanced into %v (%v)", advanced, err)
	}
	last, _, err := change(updatev1.RolloutChange_ACTION_ADVANCE).Apply(advanced)
	if err != nil || last.GetWave() != 2 {
		t.Fatalf("advanced into %v (%v)", last, err)
	}
	aborted, _, err := change(updatev1.RolloutChange_ACTION_ABORT).Apply(paused)
	if err != nil || aborted.GetState() != updatev1.RolloutRecord_STATE_ABORTED {
		t.Fatalf("aborted into %v (%v)", aborted, err)
	}

	for name, refused := range map[string]struct {
		action updatev1.RolloutChange_Action
		held   *updatev1.RolloutRecord
	}{
		"pausing a paused rollout":         {updatev1.RolloutChange_ACTION_PAUSE, paused},
		"resuming an active rollout":       {updatev1.RolloutChange_ACTION_RESUME, active},
		"advancing a paused rollout":       {updatev1.RolloutChange_ACTION_ADVANCE, paused},
		"advancing past the last wave":     {updatev1.RolloutChange_ACTION_ADVANCE, last},
		"aborting an aborted rollout":      {updatev1.RolloutChange_ACTION_ABORT, aborted},
		"resuming an aborted rollout":      {updatev1.RolloutChange_ACTION_RESUME, aborted},
		"pausing an aborted rollout":       {updatev1.RolloutChange_ACTION_PAUSE, aborted},
		"advancing an aborted rollout":     {updatev1.RolloutChange_ACTION_ADVANCE, aborted},
		"aborting a superseded rollout":    {updatev1.RolloutChange_ACTION_ABORT, superseded(active)},
		"resuming a superseded rollout":    {updatev1.RolloutChange_ACTION_RESUME, superseded(active)},
		"advancing a superseded rollout":   {updatev1.RolloutChange_ACTION_ADVANCE, superseded(active)},
		"pausing a superseded rollout":     {updatev1.RolloutChange_ACTION_PAUSE, superseded(active)},
		"advancing a rollout of one wave":  {updatev1.RolloutChange_ACTION_ADVANCE, oneWave(t)},
		"aborting what is not in force at": {updatev1.RolloutChange_ACTION_ABORT, superseded(paused)},
	} {
		if _, _, err := change(refused.action).Apply(refused.held); !errors.Is(err, agentupdate.ErrRolloutState) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func superseded(record *updatev1.RolloutRecord) *updatev1.RolloutRecord {
	return &updatev1.RolloutRecord{RolloutId: record.GetRolloutId(), Rollout: record.GetRollout(), State: updatev1.RolloutRecord_STATE_SUPERSEDED}
}

func oneWave(t *testing.T) *updatev1.RolloutRecord {
	t.Helper()
	accepted, err := agentupdate.AcceptRollout(&updatev1.Rollout{
		TenantId: "acme", Version: "v0.3.0", Waves: []*updatev1.Wave{{Percent: 100}}, Failures: 1,
	}, "ops", written)
	if err != nil {
		t.Fatal(err)
	}
	return accepted.Record
}

func TestAChangeNamesARolloutOfATenantAndWhatToDoWithIt(t *testing.T) {
	for name, asked := range map[string]*updatev1.RolloutChange{
		"no tenant":        {RolloutId: "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b", Action: updatev1.RolloutChange_ACTION_PAUSE},
		"no action":        {TenantId: "acme", RolloutId: "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b"},
		"an action":        {TenantId: "acme", RolloutId: "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b", Action: 9},
		"a long note":      {TenantId: "acme", RolloutId: "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b", Action: updatev1.RolloutChange_ACTION_PAUSE, Note: strings.Repeat("n", 513)},
		"an upper-case id": {TenantId: "acme", RolloutId: "3F0E2A64-6F53-4B6F-9A51-2C1D2E3F4A5B", Action: updatev1.RolloutChange_ACTION_PAUSE},
	} {
		_, err := agentupdate.AcceptChange(asked, "lead", written)
		if !errors.Is(err, agentupdate.ErrMalformed) && !errors.Is(err, agentupdate.ErrRolloutUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := agentupdate.AcceptChange(&updatev1.RolloutChange{
		TenantId: "acme", RolloutId: "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5b", Action: updatev1.RolloutChange_ACTION_PAUSE,
	}, "", written); !errors.Is(err, agentupdate.ErrNoActor) {
		t.Errorf("a change nobody made was taken: %v", err)
	}
	for _, id := range []string{"", "3f0e2a64", "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5", "3f0e2a64x6f53-4b6f-9a51-2c1d2e3f4a5b", "3f0e2a64-6f53-4b6f-9a51-2c1d2e3f4a5g"} {
		if agentupdate.ValidRolloutID(id) {
			t.Errorf("%q names a rollout", id)
		}
	}
}

func TestAReleaseAssignedOneByOneOutweighsTheRolloutOfTheTenant(t *testing.T) {
	accepted, err := agentupdate.AcceptRollout(canaryThenEveryone("web-01"), "ops", written)
	if err != nil {
		t.Fatal(err)
	}
	if got := agentupdate.Wanted("v0.2.1", accepted.Record, true, "web-01"); got != "v0.2.1" {
		t.Fatalf("an agent assigned v0.2.1 is asked to run %q", got)
	}
	if got := agentupdate.Wanted("", accepted.Record, true, "web-01"); got != "v0.3.0" {
		t.Fatalf("the canary of the rollout is asked to run %q", got)
	}
	if got := agentupdate.Wanted("", nil, false, "web-01"); got != "" {
		t.Fatalf("an agent nothing names is asked to run %q", got)
	}
}
