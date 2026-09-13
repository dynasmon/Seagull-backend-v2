//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisorystore"
	"github.com/dynasmon/Seagull-backend-v2/internal/clickhouse"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

// What the platform believes about one package in one release, stated once:
// the entries of the newest version of each advisory, read with the newest
// rules that version was stored under, leaving out an advisory whose newest
// version withdrew it. The newest version is found among the advisories and not
// among the entries, so a version that stopped naming the package takes the
// package out of the answer. Every matcher reads intelligence through this.
const currentAffected = `
	SELECT entry.advisory_id, entry.event_kinds, entry.event_versions
	FROM vulnerability_affected AS entry FINAL
	INNER JOIN (
		SELECT source, advisory_id, max((modified, normalization)) AS newest
		FROM vulnerability_advisories
		WHERE (source, advisory_id) IN (
			SELECT source, advisory_id FROM vulnerability_affected WHERE ecosystem = ? AND package = ?)
		GROUP BY source, advisory_id
	) AS version
	ON entry.source = version.source AND entry.advisory_id = version.advisory_id
	WHERE entry.ecosystem = ? AND entry.package = ?
	  AND (entry.modified, entry.normalization) = version.newest
	  AND entry.withdrawn = toDateTime64(0, 3, 'UTC')
	ORDER BY entry.advisory_id, entry.entry`

// How fresh the platform's copy of a feed is: its newest attempt says when it
// was asked and what came of it, and carries when it was last whole.
const feedFreshness = `
	SELECT argMax(outcome, checked_at), max(checked_at), argMax(synced_at, checked_at), argMax(newest_listed, checked_at)
	FROM vulnerability_feed_syncs
	WHERE source = ? AND feed = ?`

func migratedAdvisoryStore(t *testing.T, address string) *clickhouse.AdvisoryStore {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	migrator, err := clickhouse.NewMigrator(storeSettings(address))
	if err != nil {
		t.Fatalf("build the migrator: %v", err)
	}
	if _, err := migrator.Apply(ctx); err != nil {
		t.Fatalf("apply the schema: %v", err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatalf("close the migrator: %v", err)
	}

	store, err := clickhouse.NewAdvisoryStore(storeSettings(address))
	if err != nil {
		t.Fatalf("build the advisory store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.VerifySchema(ctx); err != nil {
		t.Fatalf("a freshly migrated store did not pass verification: %v", err)
	}
	return store
}

// Advisories are platform-wide rather than a tenant's, so each test owns the
// names nobody else writes under.
func owned(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func version(id, pkg string, modified time.Time, normalization uint32, fixedIn ...string) *vulnerabilityv1.Advisory {
	made := &vulnerabilityv1.Advisory{
		SchemaVersion: 1,
		Source:        "osv",
		Id:            id,
		Modified:      timestamppb.New(modified),
		Upstream:      []string{"CVE-2026-0001"},
		Provenance: &vulnerabilityv1.Provenance{
			Feed:          "Debian",
			FeedVersion:   `"generation-1"`,
			Location:      "https://osv.example/Debian/" + id + ".json",
			FetchedAt:     timestamppb.New(modified.Add(time.Hour)),
			Digest:        strings.Repeat("ab", 32),
			Format:        "osv 1.9.0",
			Normalization: normalization,
		},
	}
	for _, fix := range fixedIn {
		made.Affected = append(made.Affected, &vulnerabilityv1.Affected{
			Ecosystem: "Debian:12",
			Name:      pkg,
			Ranges: []*vulnerabilityv1.Range{{Type: vulnerabilityv1.Range_TYPE_ECOSYSTEM, Events: []*vulnerabilityv1.Event{
				{Boundary: &vulnerabilityv1.Event_Introduced{Introduced: "0"}},
				{Boundary: &vulnerabilityv1.Event_Fixed{Fixed: fix}},
			}}},
		})
	}
	return made
}

func hold(t *testing.T, store *clickhouse.AdvisoryStore, records ...*vulnerabilityv1.Record) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var projected advisorystore.Projection
	for _, record := range records {
		rows := advisorystore.Project(record)
		projected.Advisories = append(projected.Advisories, rows.Advisories...)
		projected.Affected = append(projected.Affected, rows.Affected...)
		projected.Syncs = append(projected.Syncs, rows.Syncs...)
	}
	if err := store.Store(ctx, projected); err != nil {
		t.Fatalf("store the advisories: %v", err)
	}
}

func advised(made *vulnerabilityv1.Advisory) *vulnerabilityv1.Record {
	return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Advisory{Advisory: made}}
}

type believed struct {
	advisory string
	fixedIn  string
}

func affecting(t *testing.T, address, pkg string) []believed {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	rows, err := inspector(t, address).Query(ctx, currentAffected, "Debian:12", pkg, "Debian:12", pkg)
	if err != nil {
		t.Fatalf("read what affects %s: %v", pkg, err)
	}
	defer func() { _ = rows.Close() }()

	var found []believed
	for rows.Next() {
		var (
			id              string
			kinds, versions []string
		)
		if err := rows.Scan(&id, &kinds, &versions); err != nil {
			t.Fatalf("read what affects %s: %v", pkg, err)
		}
		fixed := ""
		if at := slices.Index(kinds, "fixed"); at >= 0 {
			fixed = versions[at]
		}
		found = append(found, believed{advisory: id, fixedIn: fixed})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read what affects %s: %v", pkg, err)
	}
	return found
}

func TestTheAdvisoryStoreKeepsEveryFieldAnAdvisoryCarries(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	id := "DSA-" + owned(t) + "-1"
	modified := time.Date(2026, time.September, 12, 11, 0, 5, 986201214, time.UTC)

	made := version(id, "libpng1.6", modified, 1, "1.6.39-2+deb12u4")
	made.Severities = []*vulnerabilityv1.Severity{{Type: vulnerabilityv1.Severity_TYPE_UBUNTU, Score: "medium", AssessedBy: "SELF"}}
	hold(t, store, advised(made))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var (
		stored, fetchedAt           time.Time
		feed, location, digest      string
		severities, upstream        []string
		affected, normalization     uint32
		ecosystem, pkg, kind, fixed string
	)
	err := inspector(t, address).QueryRow(ctx, `
		SELECT modified, fetched_at, feed, location, digest, severity_types, upstream, affected, normalization
		FROM vulnerability_advisories FINAL WHERE advisory_id = ?`, id,
	).Scan(&stored, &fetchedAt, &feed, &location, &digest, &severities, &upstream, &affected, &normalization)
	if err != nil {
		t.Fatalf("read the version back: %v", err)
	}
	if !stored.Equal(modified) {
		t.Errorf("the version was modified at %v and is stored as %v: the version is its modification time to the nanosecond", modified, stored)
	}
	if feed != "Debian" || !strings.HasSuffix(location, id+".json") || digest != strings.Repeat("ab", 32) || normalization != 1 || !fetchedAt.Equal(modified.Add(time.Hour).Truncate(time.Millisecond)) {
		t.Errorf("the provenance read back as %s %s %s %d %v", feed, location, digest, normalization, fetchedAt)
	}
	if !slices.Equal(severities, []string{"ubuntu"}) || !slices.Equal(upstream, []string{"CVE-2026-0001"}) || affected != 1 {
		t.Errorf("read back %v %v %d", severities, upstream, affected)
	}

	err = inspector(t, address).QueryRow(ctx, `
		SELECT ecosystem, package, event_kinds[2], event_versions[2]
		FROM vulnerability_affected FINAL WHERE advisory_id = ?`, id,
	).Scan(&ecosystem, &pkg, &kind, &fixed)
	if err != nil {
		t.Fatalf("read the affected package back: %v", err)
	}
	if ecosystem != "Debian:12" || pkg != "libpng1.6" || kind != "fixed" || fixed != "1.6.39-2+deb12u4" {
		t.Errorf("the affected package read back as %s %s %s %s", ecosystem, pkg, kind, fixed)
	}
}

func TestAReplayedAdvisoryIsOneRowInEachTable(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	id := "DSA-" + owned(t) + "-1"
	made := advised(version(id, "curl", time.Now().UTC().Truncate(time.Millisecond), 1, "8.5.0-2", "8.6.0-1"))

	hold(t, store, made)
	hold(t, store, made)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var versions, entries uint64
	if err := inspector(t, address).QueryRow(ctx, "SELECT count() FROM vulnerability_advisories FINAL WHERE advisory_id = ?", id).Scan(&versions); err != nil {
		t.Fatalf("count versions: %v", err)
	}
	if err := inspector(t, address).QueryRow(ctx, "SELECT count() FROM vulnerability_affected FINAL WHERE advisory_id = ?", id).Scan(&entries); err != nil {
		t.Fatalf("count entries: %v", err)
	}
	if versions != 1 || entries != 2 {
		t.Errorf("a version stored twice is %d versions with %d entries, want 1 with 2", versions, entries)
	}
}

func TestWhatAffectsAPackageIsTheNewestVersionOfEveryAdvisoryThatStillNamesIt(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	suffix := owned(t)
	pkg := "openssl-" + suffix
	amended, dropped, withdrawn := "DSA-"+suffix+"-1", "DSA-"+suffix+"-2", "DSA-"+suffix+"-3"
	earlier, later := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, time.September, 2, 0, 0, 0, 0, time.UTC)

	gone := version(withdrawn, pkg, later, 1, "3.0.0-1")
	gone.Withdrawn = timestamppb.New(later)
	hold(t, store,
		advised(version(amended, pkg, earlier, 1, "3.0.11-1")),
		advised(version(amended, pkg, later, 1, "3.0.13-1")),
		advised(version(dropped, pkg, earlier, 1, "3.0.2-1")),
		advised(version(dropped, "not-"+pkg, later, 1, "3.0.2-1")),
		advised(version(withdrawn, pkg, earlier, 1, "3.0.0-1")),
		advised(gone),
	)

	if got, want := affecting(t, address, pkg), []believed{{advisory: amended, fixedIn: "3.0.13-1"}}; !slices.Equal(got, want) {
		t.Errorf("%s is affected by %v, want %v", pkg, got, want)
	}
}

func TestANewerReadingOfAVersionSupersedesWhatTheOlderOneSaid(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	suffix := owned(t)
	pkg := "curl-" + suffix
	id := "DSA-" + suffix + "-1"
	modified := time.Date(2026, time.September, 1, 0, 0, 0, 0, time.UTC)

	hold(t, store, advised(version(id, pkg, modified, 1, "8.5.0-2", "8.6.0-1")))
	hold(t, store, advised(version(id, pkg, modified, 2, "8.6.0-1")))

	if got, want := affecting(t, address, pkg), []believed{{advisory: id, fixedIn: "8.6.0-1"}}; !slices.Equal(got, want) {
		t.Errorf("after a newer reading %s is affected by %v, want %v: an entry the older reading had must not survive it", pkg, got, want)
	}
}

func TestTheFreshnessOfAFeedIsReadFromItsNewestAttempt(t *testing.T) {
	address := storeAddress(t)
	store := migratedAdvisoryStore(t, address)
	feed := "feed-" + owned(t)
	whole, failed := time.Date(2026, time.September, 13, 10, 0, 0, 0, time.UTC), time.Date(2026, time.September, 13, 11, 0, 0, 0, time.UTC)
	listed := time.Date(2026, time.September, 13, 9, 30, 0, 0, time.UTC)

	hold(t, store,
		&vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Sync{Sync: &vulnerabilityv1.FeedSync{
			Source: "osv", Feed: feed, Outcome: vulnerabilityv1.FeedSync_OUTCOME_COMPLETE,
			CheckedAt: timestamppb.New(whole), SyncedAt: timestamppb.New(whole), NewestListed: timestamppb.New(listed), Listed: 2, Held: 2,
		}}},
		&vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Sync{Sync: &vulnerabilityv1.FeedSync{
			Source: "osv", Feed: feed, Outcome: vulnerabilityv1.FeedSync_OUTCOME_FAILED,
			CheckedAt: timestamppb.New(failed), SyncedAt: timestamppb.New(whole), NewestListed: timestamppb.New(listed), Held: 2,
			Failure: "the index could not be read: osv.example answered 503",
		}}},
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var (
		outcome                 string
		checked, synced, newest time.Time
	)
	if err := inspector(t, address).QueryRow(ctx, feedFreshness, "osv", feed).Scan(&outcome, &checked, &synced, &newest); err != nil {
		t.Fatalf("read the freshness of the feed: %v", err)
	}
	if outcome != "failed" || !checked.Equal(failed) || !synced.Equal(whole) || !newest.Equal(listed) {
		t.Errorf("the feed reads as %s, asked at %v, whole at %v, listing up to %v", outcome, checked, synced, newest)
	}
}
