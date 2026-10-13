//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agent"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentupdate"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	updatev1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/update/v1"
)

// A tenant of its own with three agents, and a catalog naming v0.2.0 and
// v0.3.0 newer than anything the shared database held.
type rolloutEstate struct {
	store           *postgres.Store
	tenant          string
	agents          []string
	current, target agentupdate.AcceptedPackage
	rollouts        *postgres.AgentRollouts
	updates         *postgres.AgentUpdates
}

func newRolloutEstate(t *testing.T, ctx context.Context) rolloutEstate {
	t.Helper()
	store := migratedAlertStore(t, alertStoreAddress(t))
	estate := rolloutEstate{
		store: store, tenant: isolated(t),
		current: randomPackage(t), target: randomPackage(t),
		rollouts: store.AgentRollouts(), updates: store.AgentUpdates(),
	}
	for range 3 {
		estate.agents = append(estate.agents, registeredIn(t, ctx, store, estate.tenant))
	}
	slices.Sort(estate.agents)
	for _, given := range []agentupdate.AcceptedPackage{estate.current, estate.target} {
		if _, err := estate.updates.PublishPackage(ctx, given); err != nil {
			t.Fatalf("give a package: %v", err)
		}
	}
	authority := newUpdateAuthority(t)
	version := newestCatalogVersion(t, ctx, estate.updates, estate.agents[0]) + 1
	if _, err := estate.updates.PublishCatalog(ctx, authority.catalog(t, authority.anchor(t, 1), version,
		releaseFor("v0.2.0", estate.current), releaseFor("v0.3.0", estate.target))); err != nil {
		t.Fatalf("record catalog %d: %v", version, err)
	}
	return estate
}

func (e rolloutEstate) start(t *testing.T, ctx context.Context, rollout *updatev1.Rollout) *updatev1.RolloutRecord {
	t.Helper()
	accepted, err := agentupdate.AcceptRollout(rollout, "it-admin", time.Now())
	if err != nil {
		t.Fatalf("accept the rollout: %v", err)
	}
	record, err := e.rollouts.Start(ctx, accepted)
	if err != nil {
		t.Fatalf("start the rollout: %v", err)
	}
	return record
}

func (e rolloutEstate) change(t *testing.T, ctx context.Context, id string, action updatev1.RolloutChange_Action) *updatev1.RolloutRecord {
	t.Helper()
	accepted, err := agentupdate.AcceptChange(&updatev1.RolloutChange{TenantId: e.tenant, RolloutId: id, Action: action}, "it-admin", time.Now())
	if err != nil {
		t.Fatalf("accept the change: %v", err)
	}
	changed, err := e.rollouts.Change(ctx, accepted)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return changed
}

func (e rolloutEstate) asked(t *testing.T, ctx context.Context) []string {
	t.Helper()
	versions := make([]string, len(e.agents))
	for index, id := range e.agents {
		served, err := e.updates.Served(ctx, id, 0)
		if err != nil {
			t.Fatalf("ask what %s runs: %v", id, err)
		}
		versions[index] = served.Version
	}
	return versions
}

func canaryOf(tenant, canary string) *updatev1.Rollout {
	return &updatev1.Rollout{
		TenantId: tenant,
		Version:  "v0.3.0",
		Waves: []*updatev1.Wave{
			{AgentIds: []string{canary}, Soak: durationpb.New(time.Hour), Running: 1},
			{Percent: 100},
		},
		Failures: 1,
		Note:     "a canary first",
	}
}

func TestARolloutTakesOverFromTheOneInForceInItsTenantOnPostgresql(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	estate := newRolloutEstate(t, ctx)

	first := estate.start(t, ctx, canaryOf(estate.tenant, estate.agents[0]))
	time.Sleep(2 * time.Millisecond)
	named := canaryOf(estate.tenant, estate.agents[1])
	named.AgentIds = estate.agents[1:]
	second := estate.start(t, ctx, named)

	if held, err := estate.rollouts.Rollout(ctx, estate.tenant, first.GetRolloutId(), []string{estate.tenant}); err != nil ||
		held.GetState() != updatev1.RolloutRecord_STATE_SUPERSEDED || held.GetChangedBy() != "it-admin" {
		t.Fatalf("the rollout taken over from stands at %v: %v", held, err)
	}
	held, err := estate.rollouts.Rollout(ctx, estate.tenant, second.GetRolloutId(), []string{estate.tenant})
	if err != nil || held.GetState() != updatev1.RolloutRecord_STATE_ACTIVE || !slices.Equal(held.GetRollout().GetAgentIds(), estate.agents[1:]) ||
		held.GetRollout().GetWaves()[0].GetSoak().AsDuration() != time.Hour {
		t.Fatalf("the rollout in force reads %v: %v", held, err)
	}
	if _, err := estate.rollouts.Rollout(ctx, estate.tenant, second.GetRolloutId(), []string{isolated(t)}); !errors.Is(err, agentupdate.ErrRolloutUnknown) {
		t.Fatalf("a rollout was read outside the tenants the caller holds: %v", err)
	}

	page, err := estate.rollouts.Page(ctx, &updatev1.RolloutQuery{Limit: 1}, []string{estate.tenant})
	if err != nil || len(page.GetRollouts()) != 1 || page.GetRollouts()[0].GetRolloutId() != second.GetRolloutId() ||
		len(page.GetRollouts()[0].GetRollout().GetAgentIds()) != 0 || page.GetNextCursor() == "" {
		t.Fatalf("the first page is %v: %v", page, err)
	}
	next, err := estate.rollouts.Page(ctx, &updatev1.RolloutQuery{Limit: 1, Cursor: page.GetNextCursor()}, []string{estate.tenant})
	if err != nil || len(next.GetRollouts()) != 1 || next.GetRollouts()[0].GetRolloutId() != first.GetRolloutId() || next.GetNextCursor() != "" {
		t.Fatalf("the second page is %v: %v", next, err)
	}
	if _, err := estate.rollouts.Page(ctx, &updatev1.RolloutQuery{Cursor: "not-a-cursor"}, []string{estate.tenant}); !errors.Is(err, agentupdate.ErrRolloutCursor) {
		t.Fatalf("a cursor nobody issued was read: %v", err)
	}

	uncataloged := canaryOf(estate.tenant, estate.agents[0])
	uncataloged.Version = "v9.0.0"
	outsider := registeredIn(t, ctx, estate.store, isolated(t))
	for want, asked := range map[error]*updatev1.Rollout{
		agentupdate.ErrUncataloged:  uncataloged,
		agentupdate.ErrUnregistered: canaryOf(estate.tenant, outsider),
	} {
		accepted, err := agentupdate.AcceptRollout(asked, "it-admin", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := estate.rollouts.Start(ctx, accepted); !errors.Is(err, want) {
			t.Errorf("a rollout was started with %v, and %v was expected", err, want)
		}
	}
}

func TestRolloutsStartedAtOnceInOneTenantLeaveOneInForceOnPostgresql(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	estate := newRolloutEstate(t, ctx)

	var wins sync.WaitGroup
	for index := range 4 {
		accepted, err := agentupdate.AcceptRollout(canaryOf(estate.tenant, estate.agents[index%3]), "it-admin", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		wins.Go(func() {
			if _, err := estate.rollouts.Start(ctx, accepted); err != nil {
				t.Errorf("start a rollout: %v", err)
			}
		})
	}
	wins.Wait()
	page, err := estate.rollouts.Page(ctx, &updatev1.RolloutQuery{}, []string{estate.tenant})
	if err != nil || len(page.GetRollouts()) != 4 {
		t.Fatalf("the tenant holds %v: %v", page, err)
	}
	inForce := 0
	for _, held := range page.GetRollouts() {
		if agentupdate.InForce(held.GetState()) {
			inForce++
		}
	}
	if inForce != 1 {
		t.Fatalf("%d rollouts are in force in one tenant", inForce)
	}
}

func TestAnAgentIsAskedToRunWhatTheOpenWavesOfItsTenantsRolloutReachOnPostgresql(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	estate := newRolloutEstate(t, ctx)
	canary, rest := estate.agents[0], estate.agents[1:]

	started := estate.start(t, ctx, canaryOf(estate.tenant, canary))
	if got := estate.asked(t, ctx); !slices.Equal(got, []string{"v0.3.0", "", ""}) {
		t.Fatalf("with the canary's wave open the agents are asked to run %v", got)
	}
	handed, err := estate.updates.Package(ctx, canary, estate.target.Record.GetSha256())
	if err != nil || !bytes.Equal(handed.Content, estate.target.Content) {
		t.Fatalf("the canary was not handed the package of v0.3.0: %v", err)
	}
	if handed, err := estate.updates.Package(ctx, canary, estate.current.Record.GetSha256()); err != nil || !bytes.Equal(handed.Content, estate.current.Content) {
		t.Fatalf("the canary was not handed the package it would go back to: %v", err)
	}
	if _, err := estate.updates.Package(ctx, rest[0], estate.target.Record.GetSha256()); !errors.Is(err, agentupdate.ErrUnknown) {
		t.Fatalf("an agent no open wave reaches was handed a package: %v", err)
	}

	estate.change(t, ctx, started.GetRolloutId(), updatev1.RolloutChange_ACTION_ADVANCE)
	if got := estate.asked(t, ctx); !slices.Equal(got, []string{"v0.3.0", "v0.3.0", "v0.3.0"}) {
		t.Fatalf("with every wave open the agents are asked to run %v", got)
	}

	accepted, err := agentupdate.AcceptAssignment(&updatev1.Assignment{TenantId: estate.tenant, AgentIds: rest[:1], Version: "v0.2.0"}, "it-admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := estate.updates.Assign(ctx, accepted); err != nil {
		t.Fatalf("assign v0.2.0: %v", err)
	}
	if got := estate.asked(t, ctx); !slices.Equal(got, []string{"v0.3.0", "v0.2.0", "v0.3.0"}) {
		t.Fatalf("with one agent assigned v0.2.0 the agents are asked to run %v", got)
	}

	estate.change(t, ctx, started.GetRolloutId(), updatev1.RolloutChange_ACTION_PAUSE)
	if got := estate.asked(t, ctx); !slices.Equal(got, []string{"", "v0.2.0", ""}) {
		t.Fatalf("with the rollout paused the agents are asked to run %v", got)
	}
	estate.change(t, ctx, started.GetRolloutId(), updatev1.RolloutChange_ACTION_ABORT)
	if got := estate.asked(t, ctx); !slices.Equal(got, []string{"", "v0.2.0", ""}) {
		t.Fatalf("with the rollout aborted the agents are asked to run %v", got)
	}

	named := canaryOf(estate.tenant, canary)
	named.AgentIds = []string{canary}
	named.Waves = []*updatev1.Wave{{Percent: 100}}
	estate.start(t, ctx, named)
	if got := estate.asked(t, ctx); !slices.Equal(got, []string{"v0.3.0", "v0.2.0", ""}) {
		t.Fatalf("with a rollout of one agent the agents are asked to run %v", got)
	}
}

func TestAReadingIsWrittenOnlyWhileTheRolloutStandsWhereItWasReadOnPostgresql(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	estate := newRolloutEstate(t, ctx)
	started := estate.start(t, ctx, canaryOf(estate.tenant, estate.agents[0]))

	pinned, err := agentupdate.AcceptAssignment(&updatev1.Assignment{TenantId: estate.tenant, AgentIds: estate.agents[2:], Version: "v0.2.0"}, "it-admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := estate.updates.Assign(ctx, pinned); err != nil {
		t.Fatalf("assign v0.2.0: %v", err)
	}
	if _, err := estate.store.Agents().Move(ctx, estate.agents[1], []string{estate.tenant}, agent.Move{
		To: agent.Disabled, Note: "rebuilt", Actor: "it-admin", At: time.Now(),
	}); err != nil {
		t.Fatalf("disable an agent: %v", err)
	}

	held := heldRollout(t, ctx, estate.rollouts, started.GetRolloutId())
	if held.Named || held.Changes != 0 {
		t.Fatalf("a rollout just started is held as %+v", held)
	}
	reach, err := estate.rollouts.Reach(ctx, held)
	if err != nil || !slices.Equal(reach.Agents, []string{estate.agents[0], estate.agents[2]}) || !reach.Pinned[estate.agents[2]] || len(reach.Acknowledged) != 0 {
		t.Fatalf("the rollout reaches %+v: %v", reach, err)
	}

	read := copied(held.Record)
	read.Progress = &updatev1.RolloutProgress{Agents: 2, Reached: 1, Failed: 1}
	paused := agentupdate.Paused(read, "1 of the agents reached failed v0.3.0", time.Now())
	written, err := estate.rollouts.Settle(ctx, agentupdate.Settled{Held: held, Record: paused, Moved: true, Failing: []string{estate.agents[0]}})
	if err != nil || !written {
		t.Fatalf("the first reading was not written: %v", err)
	}
	after := heldRollout(t, ctx, estate.rollouts, started.GetRolloutId())
	if after.Changes != 1 || after.Record.GetState() != updatev1.RolloutRecord_STATE_PAUSED || after.Record.GetChangedBy() != agentupdate.Platform ||
		after.Record.GetProgress().GetFailed() != 1 {
		t.Fatalf("after the reading that paused it the rollout is held as %+v", after)
	}
	if written, err := estate.rollouts.Settle(ctx, agentupdate.Settled{Held: held, Record: read}); err != nil || written {
		t.Fatalf("a reading taken before the pause was written over it: %v", err)
	}

	estate.change(t, ctx, started.GetRolloutId(), updatev1.RolloutChange_ACTION_RESUME)
	resumed := heldRollout(t, ctx, estate.rollouts, started.GetRolloutId())
	if resumed.Record.GetState() != updatev1.RolloutRecord_STATE_ACTIVE || resumed.Changes != 2 {
		t.Fatalf("a resumed rollout is held as %+v", resumed)
	}
	if reach, err := estate.rollouts.Reach(ctx, resumed); err != nil || !reach.Acknowledged[estate.agents[0]] || len(reach.Acknowledged) != 1 {
		t.Fatalf("resuming took %v as known: %v", reach.Acknowledged, err)
	}

	opened := agentupdate.Opened(resumed.Record, "the canary runs it", time.Now())
	estate.change(t, ctx, started.GetRolloutId(), updatev1.RolloutChange_ACTION_PAUSE)
	if written, err := estate.rollouts.Settle(ctx, agentupdate.Settled{Held: resumed, Record: opened, Moved: true}); err != nil || written {
		t.Fatalf("a reading taken before the operator paused the rollout was written: %v", err)
	}
	if again := heldRollout(t, ctx, estate.rollouts, started.GetRolloutId()); again.Record.GetState() != updatev1.RolloutRecord_STATE_PAUSED || again.Record.GetWave() != 0 {
		t.Fatalf("the paused rollout is held as %+v", again)
	}
}

func heldRollout(t *testing.T, ctx context.Context, rollouts *postgres.AgentRollouts, id string) agentupdate.Held {
	t.Helper()
	held, err := rollouts.InForce(ctx)
	if err != nil {
		t.Fatalf("list the rollouts in force: %v", err)
	}
	for _, one := range held {
		if one.Record.GetRolloutId() == id {
			return one
		}
	}
	t.Fatalf("rollout %s is not in force", id)
	return agentupdate.Held{}
}

func copied(record *updatev1.RolloutRecord) *updatev1.RolloutRecord {
	return &updatev1.RolloutRecord{
		RolloutId: record.GetRolloutId(), Rollout: record.GetRollout(), State: record.GetState(), Wave: record.GetWave(),
		WaveOpenedAt: record.GetWaveOpenedAt(), CreatedBy: record.GetCreatedBy(), CreatedAt: record.GetCreatedAt(),
		ChangedBy: record.GetChangedBy(), ChangedAt: record.GetChangedAt(), Reason: record.GetReason(),
	}
}
