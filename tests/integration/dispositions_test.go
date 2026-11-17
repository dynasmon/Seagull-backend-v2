//go:build integration

package integration_test

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/disposition"
	"github.com/dynasmon/Seagull-backend-v2/internal/postgres"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type disposed struct {
	tenant        string
	vulnerability string
	agent         string
	kind          vulnerabilityv1.DispositionKind
	at            time.Time
	lasting       time.Duration
}

func dispose(t *testing.T, ctx context.Context, store *postgres.Store, asked disposed) *vulnerabilityv1.Disposition {
	t.Helper()
	if asked.kind == vulnerabilityv1.DispositionKind_DISPOSITION_KIND_UNSPECIFIED {
		asked.kind = vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK
	}
	if asked.lasting == 0 {
		asked.lasting = 30 * 24 * time.Hour
	}
	made, err := disposition.Record(&vulnerabilityv1.DispositionRequest{
		TenantId:        asked.tenant,
		VulnerabilityId: asked.vulnerability,
		AgentId:         asked.agent,
		Kind:            asked.kind,
		Reason:          "a compensating control covers it",
		ExpiresAt:       timestamppb.New(asked.at.Add(asked.lasting)),
	}, "it-responder", asked.at)
	if err != nil {
		t.Fatalf("decide a disposition: %v", err)
	}
	if err := store.Dispositions().Record(ctx, made); err != nil {
		t.Fatalf("record %s: %v", made.GetDispositionId(), err)
	}
	return made
}

func search(t *testing.T, ctx context.Context, store *postgres.Store, asked *vulnerabilityv1.DispositionQuery, tenants []string, at time.Time) []*vulnerabilityv1.Disposition {
	t.Helper()
	var found []*vulnerabilityv1.Disposition
	for pages := 0; ; pages++ {
		if pages > 100 {
			t.Fatal("the listing never ended")
		}
		page, err := store.Dispositions().Page(ctx, asked, tenants, at)
		if err != nil {
			t.Fatalf("list dispositions: %v", err)
		}
		found = append(found, page.GetDispositions()...)
		if page.GetNextCursor() == "" {
			return found
		}
		asked = proto.Clone(asked).(*vulnerabilityv1.DispositionQuery)
		asked.Cursor = page.GetNextCursor()
	}
}

func dispositionIDs(listed []*vulnerabilityv1.Disposition) []string {
	ids := make([]string, 0, len(listed))
	for _, one := range listed {
		ids = append(ids, one.GetDispositionId())
	}
	return ids
}

func TestADispositionIsReadBackExactlyAsItWasRecordedOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, at := isolated(t), time.Now()
	agentID := registeredIn(t, ctx, store, tenant)
	narrowed, err := disposition.Record(&vulnerabilityv1.DispositionRequest{
		TenantId:        tenant,
		VulnerabilityId: "CVE-2026-1000",
		AgentId:         agentID,
		PackageName:     "openssl",
		Kind:            vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED,
		Reason:          "the package is installed and never loaded\nticket SEC-7",
		ExpiresAt:       timestamppb.New(at.Add(7 * 24 * time.Hour)),
	}, "it-responder", at)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if err := store.Dispositions().Record(ctx, narrowed); err != nil {
		t.Fatalf("record: %v", err)
	}
	everywhere := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-1001", at: at.Add(time.Second)})

	listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{}, []string{tenant}, at.Add(time.Minute))
	if len(listed) != 2 || !proto.Equal(listed[0], everywhere) || !proto.Equal(listed[1], narrowed) {
		t.Fatalf("read back\n%v\nwant\n%v\n%v", listed, everywhere, narrowed)
	}
}

func TestADispositionIsReachedOnlyWithinTheCallersTenantsOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ours, theirs, at := isolated(t), isolated(t), time.Now()
	kept := dispose(t, ctx, store, disposed{tenant: ours, vulnerability: "CVE-2026-2000", at: at})
	hidden := dispose(t, ctx, store, disposed{tenant: theirs, vulnerability: "CVE-2026-2001", at: at})

	for name, asked := range map[string]*vulnerabilityv1.DispositionQuery{
		"everything":                    {},
		"the other tenant's CVE":        {VulnerabilityIds: []string{"CVE-2026-2001"}},
		"lapsed ones as well":           {Lapsed: true},
		"every kind by name":            {Kinds: []vulnerabilityv1.DispositionKind{vulnerabilityv1.DispositionKind_DISPOSITION_KIND_ACCEPTED_RISK}},
		"both tenants' vulnerabilities": {VulnerabilityIds: []string{"CVE-2026-2000", "CVE-2026-2001"}},
	} {
		for _, one := range search(t, ctx, store, asked, []string{ours}, at) {
			if one.GetTenantId() != ours {
				t.Errorf("asking for %s from %s answered %s of %s", name, ours, one.GetDispositionId(), one.GetTenantId())
			}
		}
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{}, []string{ours}, at); !slices.Equal(dispositionIDs(listed), []string{kept.GetDispositionId()}) {
		t.Errorf("%s holds %v", ours, dispositionIDs(listed))
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{}, nil, at); len(listed) != 0 {
		t.Errorf("a caller holding no tenant was answered %v", dispositionIDs(listed))
	}

	withdrawal := disposition.Withdrawal{Reason: "not ours to end", Actor: "it-responder", At: at.Add(time.Minute)}
	if _, err := store.Dispositions().Withdraw(ctx, hidden.GetDispositionId(), []string{ours}, withdrawal); !errors.Is(err, disposition.ErrUnknown) {
		t.Fatalf("withdrawing a disposition of another tenant answered %v", err)
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{}, []string{theirs}, at.Add(time.Hour)); len(listed) != 1 || !proto.Equal(listed[0], hidden) {
		t.Errorf("the other tenant's disposition reads %v after a refused withdrawal", listed)
	}
}

func TestALapsedDispositionIsListedOnlyWhenAskedForOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, now := isolated(t), time.Now()
	expired := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-3000", at: now.Add(-48 * time.Hour), lasting: 24 * time.Hour})
	inForce := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-3001", at: now.Add(-time.Hour)})
	ended := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-3002", at: now.Add(-30 * time.Minute)})
	withdrawn, err := store.Dispositions().Withdraw(ctx, ended.GetDispositionId(), []string{tenant},
		disposition.Withdrawal{Reason: "the fix shipped", Actor: "it-admin", At: now.Add(-10 * time.Minute)})
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}

	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{}, []string{tenant}, now); !slices.Equal(dispositionIDs(listed), []string{inForce.GetDispositionId()}) {
		t.Errorf("in force at %s: %v", now, dispositionIDs(listed))
	}
	listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{Lapsed: true}, []string{tenant}, now)
	if len(listed) != 3 || !proto.Equal(listed[0], withdrawn) || !proto.Equal(listed[1], inForce) || !proto.Equal(listed[2], expired) {
		t.Errorf("asked with lapsed ones, read\n%v", listed)
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{}, []string{tenant}, now.Add(31*24*time.Hour)); len(listed) != 0 {
		t.Errorf("a month later, %v are still in force", dispositionIDs(listed))
	}
}

func TestAnAgentIsAnsweredWithEveryDispositionCoveringItOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, at := isolated(t), time.Now()
	web, database := registeredIn(t, ctx, store, tenant), registeredIn(t, ctx, store, tenant)
	everywhere := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-4000", at: at})
	onWeb := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-4000", agent: web, at: at.Add(time.Second),
		kind: vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED})
	onDatabase := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-4001", agent: database, at: at.Add(2 * time.Second)})

	later := at.Add(time.Minute)
	for name, check := range map[string]struct {
		asked *vulnerabilityv1.DispositionQuery
		want  []string
	}{
		"the web server":     {&vulnerabilityv1.DispositionQuery{AgentIds: []string{web}}, []string{onWeb.GetDispositionId(), everywhere.GetDispositionId()}},
		"the database":       {&vulnerabilityv1.DispositionQuery{AgentIds: []string{database}}, []string{onDatabase.GetDispositionId(), everywhere.GetDispositionId()}},
		"an unknown machine": {&vulnerabilityv1.DispositionQuery{AgentIds: []string{"it-nobody"}}, []string{everywhere.GetDispositionId()}},
		"one vulnerability":  {&vulnerabilityv1.DispositionQuery{VulnerabilityIds: []string{"CVE-2026-4000"}}, []string{onWeb.GetDispositionId(), everywhere.GetDispositionId()}},
		"ignored ones": {&vulnerabilityv1.DispositionQuery{Kinds: []vulnerabilityv1.DispositionKind{
			vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED}}, []string{onWeb.GetDispositionId()}},
		"the database's vulnerability on the web server": {&vulnerabilityv1.DispositionQuery{
			AgentIds: []string{web}, VulnerabilityIds: []string{"CVE-2026-4001"}}, nil},
	} {
		if listed := dispositionIDs(search(t, ctx, store, check.asked, []string{tenant}, later)); !slices.Equal(listed, check.want) {
			t.Errorf("%s: listed %v, want %v", name, listed, check.want)
		}
	}
}

func TestADispositionIsWithdrawnOnceOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, at := isolated(t), time.Now()
	made := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-5000", at: at})
	withdrawal := disposition.Withdrawal{Reason: "the fix shipped", Actor: "it-admin", At: at.Add(time.Second)}

	withdrawn, err := store.Dispositions().Withdraw(ctx, made.GetDispositionId(), []string{tenant}, withdrawal)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	withdrawal.At = at.Add(2 * time.Second)
	if _, err := store.Dispositions().Withdraw(ctx, made.GetDispositionId(), []string{tenant}, withdrawal); !errors.Is(err, disposition.ErrLapsed) {
		t.Errorf("withdrawing it again answered %v", err)
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{Lapsed: true}, []string{tenant}, at.Add(time.Hour)); len(listed) != 1 || !proto.Equal(listed[0], withdrawn) {
		t.Errorf("the store holds\n%v\nand the withdrawal answered\n%v", listed, withdrawn)
	}
	if _, err := store.Dispositions().Withdraw(ctx, "0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6", []string{tenant}, withdrawal); !errors.Is(err, disposition.ErrUnknown) {
		t.Errorf("withdrawing a disposition nobody recorded answered %v", err)
	}
}

// The competing withdrawal is written first and committed only once the request
// under test has read the disposition in force and waits on the key, which is
// the interleaving two people withdrawing at once can produce. The wait is
// watched from a connection of its own: a transaction reads pg_stat_activity
// once and answers with that reading until it ends.
func TestAWithdrawalThatLostTheKeyIsToldTheDispositionLapsedOnPostgresql(t *testing.T) {
	address := alertStoreAddress(t)
	store := migratedAlertStore(t, address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, at := isolated(t), time.Now()
	made := dispose(t, ctx, store, disposed{tenant: tenant, vulnerability: "CVE-2026-5001", at: at})

	beside := "postgres://" + storeUser + ":seagull@" + address + "/" + storeDatabase + "?sslmode=disable"
	side, err := pgx.Connect(ctx, beside)
	if err != nil {
		t.Fatalf("connect beside the store: %v", err)
	}
	defer func() { _ = side.Close(context.Background()) }()
	watcher, err := pgx.Connect(ctx, beside)
	if err != nil {
		t.Fatalf("connect a watcher: %v", err)
	}
	defer func() { _ = watcher.Close(context.Background()) }()
	competing, err := side.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = competing.Rollback(context.Background()) }()
	if _, err := competing.Exec(ctx, `INSERT INTO vulnerability_disposition_withdrawals (disposition_id, withdrawn_by, withdrawn_at, reason)
		VALUES ($1, 'it-colleague', $2, 'withdrawn first')`, made.GetDispositionId(), at.Add(time.Second)); err != nil {
		t.Fatalf("withdraw first: %v", err)
	}

	answered := make(chan error, 1)
	go func() {
		_, err := store.Dispositions().Withdraw(ctx, made.GetDispositionId(), []string{tenant},
			disposition.Withdrawal{Reason: "withdrawn second", Actor: "it-admin", At: at.Add(2 * time.Second)})
		answered <- err
	}()
	for waiting := 0; waiting == 0; {
		if err := watcher.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE 'INSERT INTO vulnerability_disposition_withdrawals%'`).Scan(&waiting); err != nil {
			t.Fatalf("the withdrawal under test was never seen waiting on the key: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := competing.Commit(ctx); err != nil {
		t.Fatalf("commit the first withdrawal: %v", err)
	}

	if err := <-answered; !errors.Is(err, disposition.ErrLapsed) {
		t.Fatalf("the withdrawal that lost the key answered %v", err)
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{Lapsed: true}, []string{tenant}, at.Add(time.Hour)); len(listed) != 1 ||
		listed[0].GetWithdrawnBy() != "it-colleague" || listed[0].GetWithdrawalReason() != "withdrawn first" {
		t.Errorf("the store holds %v", listed)
	}
}

func TestADispositionNamingAnAgentItsTenantNeverRegisteredIsRefusedOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, elsewhere, at := isolated(t), isolated(t), time.Now()
	foreign := registeredIn(t, ctx, store, elsewhere)

	for name, agentID := range map[string]string{
		"an agent of another tenant": foreign,
		"an agent nobody registered": agentIdentifier(t),
	} {
		made, err := disposition.Record(&vulnerabilityv1.DispositionRequest{
			TenantId:        tenant,
			VulnerabilityId: "CVE-2026-6000",
			AgentId:         agentID,
			Kind:            vulnerabilityv1.DispositionKind_DISPOSITION_KIND_IGNORED,
			Reason:          "typed the wrong machine",
			ExpiresAt:       timestamppb.New(at.Add(time.Hour)),
		}, "it-responder", at)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		if err := store.Dispositions().Record(ctx, made); !errors.Is(err, disposition.ErrUnregistered) {
			t.Errorf("%s: recording answered %v", name, err)
		}
	}
	if listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{Lapsed: true}, []string{tenant}, at); len(listed) != 0 {
		t.Errorf("refused dispositions were kept: %v", dispositionIDs(listed))
	}
}

func TestDispositionsArePagedNewestFirstAndNoneTwiceOnPostgresql(t *testing.T) {
	store := migratedAlertStore(t, alertStoreAddress(t))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tenant, at := isolated(t), time.Now().Truncate(time.Millisecond)
	var recorded []*vulnerabilityv1.Disposition
	for index, offset := range []time.Duration{0, 100 * time.Microsecond, 100 * time.Microsecond, 100 * time.Microsecond,
		200 * time.Microsecond, 300 * time.Microsecond, 300 * time.Microsecond} {
		recorded = append(recorded, dispose(t, ctx, store, disposed{
			tenant: tenant, vulnerability: "CVE-2026-700" + string(rune('0'+index)), at: at.Add(offset)}))
	}
	slices.SortFunc(recorded, func(one, other *vulnerabilityv1.Disposition) int {
		if compared := other.GetDecidedAt().AsTime().Compare(one.GetDecidedAt().AsTime()); compared != 0 {
			return compared
		}
		switch {
		case one.GetDispositionId() > other.GetDispositionId():
			return -1
		case one.GetDispositionId() < other.GetDispositionId():
			return 1
		}
		return 0
	})

	for _, limit := range []uint32{1, 2, 3, 7, 50} {
		listed := search(t, ctx, store, &vulnerabilityv1.DispositionQuery{Limit: limit}, []string{tenant}, at.Add(time.Minute))
		if !slices.Equal(dispositionIDs(listed), dispositionIDs(recorded)) {
			t.Errorf("by pages of %d: %v, want %v", limit, dispositionIDs(listed), dispositionIDs(recorded))
		}
	}
	for _, cursor := range []string{
		"not-a-cursor",
		base64.RawURLEncoding.EncodeToString([]byte("1794916800123456/../../etc")),
		base64.RawURLEncoding.EncodeToString([]byte("yesterday/0f8e4a52-1c3b-4d6e-9f70-a1b2c3d4e5f6")),
	} {
		if _, err := store.Dispositions().Page(ctx, &vulnerabilityv1.DispositionQuery{Cursor: cursor}, []string{tenant}, at); !errors.Is(err, disposition.ErrCursor) {
			t.Errorf("the cursor %q, which nobody issued, answered %v", cursor, err)
		}
	}
}
