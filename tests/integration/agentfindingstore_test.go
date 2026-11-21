//go:build integration

package integration_test

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/agentfinding"
	"github.com/dynasmon/Seagull-backend-v2/internal/agentfindingstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	agentv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/agent/v1"
	huntv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/hunt/v1"
)

func migratedAgentFindingStore(t *testing.T, address string) *clickhouse.AgentFindingStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := clickhouse.NewMigrator(storeSettings(address), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewAgentFindingStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the agent finding store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

type decision struct {
	owner, agentID, episode string
	kind                    agentv1.Finding_Kind
	opened, decided         time.Time
	closed                  bool
}

func (d decision) finding() *agentv1.Finding {
	decided := &agentv1.Finding{
		SchemaVersion:  agentfinding.SchemaVersion,
		FindingId:      agentfinding.ID(d.owner, d.agentID, d.kind, d.episode),
		TenantId:       d.owner,
		AgentId:        d.agentID,
		Kind:           d.kind,
		State:          agentv1.Finding_STATE_OPEN,
		OpenedAt:       timestamppb.New(d.opened),
		LastObservedAt: timestamppb.New(d.opened),
		Observations:   1,
		DecidedAt:      timestamppb.New(d.decided),
	}
	for index := range 2 {
		decided.Reports = append(decided.Reports, &agentv1.Heard{
			InstallationId: "installation-" + strconv.Itoa(index),
			BootId:         "boot-" + d.episode,
			Sequence:       41,
			ReportedAt:     timestamppb.New(d.opened.Add(-5 * time.Minute)),
			IngestTime:     timestamppb.New(d.opened.Add(-5 * time.Minute)),
			Gateway:        "gateway-integration",
			Interval:       durationpb.New(time.Minute),
		})
	}
	if d.closed {
		decided.State = agentv1.Finding_STATE_CLOSED
		decided.Closure = agentv1.Finding_CLOSURE_NOT_ADMITTED
		decided.ClosedAt = timestamppb.New(d.decided)
	}
	return decided
}

func (d decision) row(t *testing.T) agentfindingstore.Row {
	t.Helper()
	made := d.finding()
	if err := agentfinding.Validate(made); err != nil {
		t.Fatalf("the test made a finding the contract refuses: %v", err)
	}
	published, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a finding: %v", err)
	}
	return agentfindingstore.Project(made, published)
}

func storeDecisions(t *testing.T, store *clickhouse.AgentFindingStore, rows ...agentfindingstore.Row) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Store(ctx, rows); err != nil {
		t.Fatalf("store the decisions: %v", err)
	}
}

func openCount(t *testing.T, store *clickhouse.AgentFindingStore) map[string]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	counted, err := store.CountOpen(ctx)
	if err != nil {
		t.Fatalf("count the open findings: %v", err)
	}
	return counted
}

func searched(t *testing.T, store *clickhouse.AgentFindingStore, asked *agentv1.FindingQuery, tenants ...string) *agentv1.FindingPage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	page, err := store.Search(ctx, asked, tenants)
	if err != nil {
		t.Fatalf("search the findings: %v", err)
	}
	return page
}

func idsOf(findings []*agentv1.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, one := range findings {
		ids = append(ids, one.GetFindingId())
	}
	return ids
}

// A finding stands as its newest decision whatever order the decisions were
// stored in, and every read is held to the tenants it is asked within. The
// shared store keeps what earlier runs counted, so the count is read as a
// difference (BE-103).
func TestAFindingStandsAsItsNewestDecisionWithinTheTenantsItIsReadIn(t *testing.T) {
	address := storeAddress(t)
	store := migratedAgentFindingStore(t, address)
	owner, elsewhere := tenant(t), tenant(t)
	watched, foreign := agentIdentifier(t), agentIdentifier(t)
	before := openCount(t, store)

	now := time.Now().UTC().Truncate(time.Millisecond)
	silence := decision{owner: owner, agentID: watched, episode: "silence", kind: agentv1.Finding_KIND_SILENCE, opened: now.Add(-time.Hour), decided: now.Add(-time.Hour)}
	ended := silence
	ended.decided, ended.closed = now.Add(-time.Minute), true
	shared := decision{owner: owner, agentID: watched, episode: "shared", kind: agentv1.Finding_KIND_SHARED_IDENTITY, opened: now.Add(-30 * time.Minute), decided: now.Add(-30 * time.Minute)}
	abroad := decision{owner: elsewhere, agentID: foreign, episode: "abroad", kind: agentv1.Finding_KIND_SILENCE, opened: now, decided: now}
	storeDecisions(t, store, ended.row(t), shared.row(t), abroad.row(t))
	storeDecisions(t, store, silence.row(t))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	open, err := store.Open(ctx, []string{watched, foreign}, []string{owner})
	if err != nil {
		t.Fatalf("read the open findings: %v", err)
	}
	if len(open) != 1 || !slices.Equal(idsOf(open[watched]), []string{shared.finding().GetFindingId()}) {
		t.Fatalf("the open findings read are %v, and only the shared identity of %s is open in %s", open, watched, owner)
	}

	closed := searched(t, store, &agentv1.FindingQuery{States: []agentv1.Finding_State{agentv1.Finding_STATE_CLOSED}}, owner)
	if len(closed.GetFindings()) != 1 || closed.GetFindings()[0].GetClosure() != agentv1.Finding_CLOSURE_NOT_ADMITTED {
		t.Fatalf("the closed findings read are %v, and the silence closed after it opened", closed.GetFindings())
	}
	if page := searched(t, store, &agentv1.FindingQuery{Kinds: []agentv1.Finding_Kind{agentv1.Finding_KIND_SILENCE}, States: []agentv1.Finding_State{agentv1.Finding_STATE_OPEN}}, owner); len(page.GetFindings()) != 0 {
		t.Errorf("a silence that closed is still read open: %v", idsOf(page.GetFindings()))
	}
	if page := searched(t, store, &agentv1.FindingQuery{AgentId: foreign}, owner); len(page.GetFindings()) != 0 {
		t.Errorf("an agent of another tenant was read: %v", idsOf(page.GetFindings()))
	}
	window := &huntv1.TimeRange{Start: timestamppb.New(now.Add(-45 * time.Minute)), End: timestamppb.New(now.Add(time.Minute))}
	if page := searched(t, store, &agentv1.FindingQuery{Range: window}, owner); !slices.Equal(idsOf(page.GetFindings()), []string{shared.finding().GetFindingId()}) {
		t.Errorf("the findings opened inside the range are %v", idsOf(page.GetFindings()))
	}

	after := openCount(t, store)
	if after["shared_identity"]-before["shared_identity"] != 1 || after["silence"]-before["silence"] != 1 {
		t.Errorf("the open count moved from %v to %v, and one shared identity and one foreign silence opened", before, after)
	}
}

// Findings opened in one millisecond are paged by their identifier, so a page
// boundary inside that millisecond skips nothing and repeats nothing.
func TestFindingsArePagedWithoutLosingOneThatOpenedInTheSameMillisecond(t *testing.T) {
	address := storeAddress(t)
	store := migratedAgentFindingStore(t, address)
	owner, watched := tenant(t), agentIdentifier(t)

	now := time.Now().UTC().Truncate(time.Millisecond)
	var rows []agentfindingstore.Row
	var want []string
	for index := range 7 {
		opened := now.Add(-time.Duration(index/3) * time.Minute)
		made := decision{owner: owner, agentID: watched, episode: "paged-" + strconv.Itoa(index), kind: agentv1.Finding_KIND_SILENCE, opened: opened, decided: opened}
		rows, want = append(rows, made.row(t)), append(want, made.finding().GetFindingId())
	}
	storeDecisions(t, store, rows...)

	var read []string
	asked := &agentv1.FindingQuery{AgentId: watched, Limit: 2}
	for pages := 0; ; pages++ {
		if pages > len(want) {
			t.Fatal("the pages never ended")
		}
		page := searched(t, store, asked, owner)
		read = append(read, idsOf(page.GetFindings())...)
		if page.GetNextCursor() == "" {
			break
		}
		asked = &agentv1.FindingQuery{AgentId: watched, Limit: 2, Cursor: page.GetNextCursor()}
	}
	if len(read) != len(want) || len(slices.Compact(slices.Sorted(slices.Values(read)))) != len(want) {
		t.Fatalf("paging read %d findings, %d of them distinct, of %d stored", len(read), len(slices.Compact(slices.Sorted(slices.Values(read)))), len(want))
	}
	if !slices.Equal(slices.Sorted(slices.Values(read)), slices.Sorted(slices.Values(want))) {
		t.Errorf("paging read %v, want %v", read, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := store.Search(ctx, &agentv1.FindingQuery{Cursor: "bm90LWEtY3Vyc29y"}, []string{owner}); !errors.Is(err, agentfinding.ErrCursor) {
		t.Errorf("an invented cursor was answered %v", err)
	}
}
