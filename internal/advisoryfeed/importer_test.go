package advisoryfeed_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/advisoryfeed"
	"github.com/dynasmon/Seagull-backend-v2/internal/osv"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

var started = time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)

func record(id string, modified time.Time, fixedIn string) string {
	return fmt.Sprintf(`{"schema_version": "1.9.0", "id": %q, "modified": %q, "upstream": ["CVE-2026-0001"],
		"affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
		"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": %q}]}]}]}`,
		id, modified.Format(time.RFC3339Nano), fixedIn)
}

func digest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

type origin struct {
	mu        sync.Mutex
	indexes   map[string]advisoryfeed.Index
	indexErr  map[string]error
	records   map[string]string
	recordErr map[string]error
	asked     map[string]int
}

func newOrigin() *origin {
	return &origin{
		indexes:   map[string]advisoryfeed.Index{},
		indexErr:  map[string]error{},
		records:   map[string]string{},
		recordErr: map[string]error{},
		asked:     map[string]int{},
	}
}

func (o *origin) list(feed, version string, bodies map[string]time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	index := advisoryfeed.Index{Version: version}
	for id, modified := range bodies {
		index.Listings = append(index.Listings, advisoryfeed.Listing{ID: id, Modified: modified})
	}
	o.indexes[feed] = index
}

func (o *origin) serve(feed, id, body string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records[feed+"/"+id] = body
}

func (o *origin) times(path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.asked[path]
}

func (o *origin) Index(_ context.Context, feed, known string) (advisoryfeed.Index, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.asked[feed+"/index"]++
	if err := o.indexErr[feed]; err != nil {
		return advisoryfeed.Index{}, err
	}
	index := o.indexes[feed]
	if known != "" && known == index.Version {
		return advisoryfeed.Index{Version: known, Unchanged: true}, nil
	}
	return index, nil
}

func (o *origin) Record(_ context.Context, feed, id string) (advisoryfeed.Fetched, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	path := feed + "/" + id
	o.asked[path]++
	if err := o.recordErr[path]; err != nil {
		return advisoryfeed.Fetched{}, err
	}
	body, held := o.records[path]
	if !held {
		return advisoryfeed.Fetched{}, fmt.Errorf("%s: %w", path, advisoryfeed.ErrGone)
	}
	return advisoryfeed.Fetched{Body: []byte(body), Location: "https://osv.example/" + path + ".json"}, nil
}

type backbone struct {
	mu        sync.Mutex
	published [][]*vulnerabilityv1.Record
	refusing  int
}

func (b *backbone) Publish(_ context.Context, records []*vulnerabilityv1.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refusing > 0 {
		b.refusing--
		return errors.New("the backbone did not answer")
	}
	kept := make([]*vulnerabilityv1.Record, 0, len(records))
	for _, entry := range records {
		kept = append(kept, proto.Clone(entry).(*vulnerabilityv1.Record))
	}
	b.published = append(b.published, kept)
	return nil
}

func (b *backbone) taken() []*vulnerabilityv1.Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	var flat []*vulnerabilityv1.Record
	for _, batch := range b.published {
		flat = append(flat, batch...)
	}
	b.published = nil
	return flat
}

func advisories(records []*vulnerabilityv1.Record) map[string]*vulnerabilityv1.Advisory {
	found := map[string]*vulnerabilityv1.Advisory{}
	for _, entry := range records {
		if advisory := entry.GetAdvisory(); advisory != nil {
			found[advisory.GetId()] = advisory
		}
	}
	return found
}

func syncs(records []*vulnerabilityv1.Record) []*vulnerabilityv1.FeedSync {
	var found []*vulnerabilityv1.FeedSync
	for _, entry := range records {
		if sync := entry.GetSync(); sync != nil {
			found = append(found, sync)
		}
	}
	return found
}

type history []*vulnerabilityv1.Record

func (h history) Replay(_ context.Context, learn func(*vulnerabilityv1.Record)) error {
	for _, entry := range h {
		learn(entry)
	}
	return nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(by)
}

type harness struct {
	importer *advisoryfeed.Importer
	origin   *origin
	backbone *backbone
	clock    *clock
	registry *metrics.Registry
}

func build(t *testing.T, past history, feeds ...string) harness {
	t.Helper()
	if len(feeds) == 0 {
		feeds = []string{"Debian"}
	}
	built := harness{origin: newOrigin(), backbone: &backbone{}, clock: &clock{now: started}, registry: metrics.New(t.Name())}
	importer, err := advisoryfeed.NewImporter(advisoryfeed.Options{
		Source:        osv.Source,
		Feeds:         feeds,
		Origin:        built.origin,
		Translate:     osv.Translate,
		Normalization: osv.Normalization,
		Log:           built.backbone,
		History:       past,
		Metrics:       advisoryfeed.NewMetrics(built.registry),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Interval:      time.Hour,
		RetryDelay:    time.Millisecond,
		Backoff:       time.Millisecond,
		Attempts:      2,
		Concurrency:   4,
		Batch:         2,
		Now:           built.clock.Now,
	})
	if err != nil {
		t.Fatalf("build the importer: %v", err)
	}
	if err := importer.Recall(context.Background()); err != nil {
		t.Fatalf("recall what the platform held: %v", err)
	}
	built.importer = importer
	return built
}

func (h harness) sync(t *testing.T, feed string) (*vulnerabilityv1.FeedSync, []*vulnerabilityv1.Record) {
	t.Helper()
	returned := h.importer.Sync(context.Background(), feed)
	taken := h.backbone.taken()
	found := syncs(taken)
	if returned != nil && (len(found) != 1 || !proto.Equal(found[0], returned)) {
		t.Fatalf("the attempt reported %v and published %v", returned, found)
	}
	if len(found) > 0 && taken[len(taken)-1].GetSync() == nil {
		t.Fatal("an advisory was published after the sync that accounts for it")
	}
	return returned, taken
}

func TestAFeedIsReadIntoAdvisoriesThatSayWhereAndWhenTheyWereRead(t *testing.T) {
	h := build(t, nil)
	one, two := record("DSA-6189-1", started.Add(-2*time.Hour), "1.6.39-2+deb12u4"), record("DEBIAN-CVE-2024-58382", started.Add(-time.Hour), "2.6.0-1")
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-6189-1": started.Add(-2 * time.Hour), "DEBIAN-CVE-2024-58382": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-6189-1", one)
	h.origin.serve("Debian", "DEBIAN-CVE-2024-58382", two)

	sync, published := h.sync(t, "Debian")

	found := advisories(published)
	if len(found) != 2 {
		t.Fatalf("published %d advisories, want 2", len(found))
	}
	read := found["DSA-6189-1"].GetProvenance()
	want := &vulnerabilityv1.Provenance{
		Feed:          "Debian",
		FeedVersion:   `"generation-1"`,
		Location:      "https://osv.example/Debian/DSA-6189-1.json",
		FetchedAt:     timestamppb.New(started),
		Digest:        digest(one),
		Format:        "osv 1.9.0",
		Normalization: osv.Normalization,
	}
	if !proto.Equal(read, want) {
		t.Errorf("provenance %v, want %v", read, want)
	}
	if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE || sync.GetListed() != 2 || sync.GetHeld() != 2 || sync.GetPublished() != 2 {
		t.Errorf("the sync says %v", sync)
	}
	if !sync.GetSyncedAt().AsTime().Equal(started) || !sync.GetNewestListed().AsTime().Equal(started.Add(-time.Hour)) {
		t.Errorf("synced at %v with the newest listed at %v", sync.GetSyncedAt().AsTime(), sync.GetNewestListed().AsTime())
	}
	if exposed(t, h.registry, `seagull_advisoryfeed_synced_timestamp_seconds{feed="Debian"}`) != float64(started.Unix()) {
		t.Error("the freshness of the feed is not exposed")
	}
}

func TestAFeedThatHasNotChangedPublishesOnlyItsFreshness(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-6189-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-6189-1", record("DSA-6189-1", started.Add(-time.Hour), "1.6.39-2+deb12u4"))
	h.sync(t, "Debian")

	h.clock.advance(time.Hour)
	sync, published := h.sync(t, "Debian")

	if len(advisories(published)) != 0 {
		t.Errorf("an unchanged feed published %v", advisories(published))
	}
	if h.origin.times("Debian/DSA-6189-1") != 1 {
		t.Errorf("a record the platform already holds was asked for %d times", h.origin.times("Debian/DSA-6189-1"))
	}
	if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE || !sync.GetSyncedAt().AsTime().Equal(started.Add(time.Hour)) {
		t.Errorf("the second sync says %v", sync)
	}
}

func TestOnlyWhatChangedIsReadAgain(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-2 * time.Hour), "DSA-2": started.Add(-2 * time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-2*time.Hour), "1.0-1"))
	h.origin.serve("Debian", "DSA-2", record("DSA-2", started.Add(-2*time.Hour), "2.0-1"))
	h.sync(t, "Debian")

	h.origin.list("Debian", `"generation-2"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour), "DSA-2": started.Add(-2 * time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-2"))
	_, published := h.sync(t, "Debian")

	found := advisories(published)
	if len(found) != 1 || found["DSA-1"] == nil {
		t.Fatalf("republished %v, want only DSA-1", found)
	}
	if h.origin.times("Debian/DSA-2") != 1 {
		t.Errorf("an unchanged record was asked for %d times", h.origin.times("Debian/DSA-2"))
	}
}

func TestARecordWhoseTimeMovedAndWhoseContentDidNotIsNotAnotherVersion(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-2 * time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-2*time.Hour), "1.0-1"))
	h.sync(t, "Debian")

	h.origin.list("Debian", `"generation-2"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))
	_, published := h.sync(t, "Debian")
	if found := advisories(published); len(found) != 0 {
		t.Errorf("a record that says the same thing was published again: %v", found)
	}

	h.origin.list("Debian", `"generation-3"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.sync(t, "Debian")
	if asked := h.origin.times("Debian/DSA-1"); asked != 2 {
		t.Errorf("the record was asked for %d times, want 2: once when new and once when its time moved", asked)
	}
}

func TestAFeedThatCannotBeReadChangesNothingAndSaysWhenItWasLastWhole(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))
	h.sync(t, "Debian")

	for _, failure := range []error{
		&advisoryfeed.Unavailable{Err: errors.New("osv.example answered 503")},
		errors.New("osv.example answered 403"),
	} {
		h.clock.advance(time.Hour)
		h.origin.indexErr["Debian"] = failure
		sync, published := h.sync(t, "Debian")

		if len(advisories(published)) != 0 {
			t.Errorf("a feed that could not be read published %v", advisories(published))
		}
		if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_FAILED || sync.GetFailure() == "" {
			t.Errorf("the failed attempt says %v", sync)
		}
		if !sync.GetSyncedAt().AsTime().Equal(started) || !sync.GetCheckedAt().AsTime().Equal(h.clock.Now()) {
			t.Errorf("the failed attempt says the feed was whole at %v and asked at %v", sync.GetSyncedAt().AsTime(), sync.GetCheckedAt().AsTime())
		}
		if sync.GetHeld() != 1 {
			t.Errorf("the platform holds %d advisories after a failed attempt, want the 1 it held", sync.GetHeld())
		}
	}
	if asked := h.origin.times("Debian/index"); asked != 4 {
		t.Errorf("the index was asked for %d times, want 4: once, twice for the unavailable origin, once for the refusal", asked)
	}
	if exposed(t, h.registry, `seagull_advisoryfeed_synced_timestamp_seconds{feed="Debian"}`) != float64(started.Unix()) {
		t.Error("a failed attempt moved the freshness of the feed")
	}
}

func TestAFeedThatWasNeverReadSaysSo(t *testing.T) {
	h := build(t, nil)
	h.origin.indexErr["Debian"] = errors.New("osv.example answered 404")

	sync, _ := h.sync(t, "Debian")
	if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_FAILED || sync.GetSyncedAt() != nil {
		t.Errorf("a feed never read says %v", sync)
	}
}

func TestARecordTheOriginCannotServeLeavesTheSyncOwingItAndKeepsWhatWasRead(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour), "DSA-2": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))
	h.origin.serve("Debian", "DSA-2", record("DSA-2", started.Add(-time.Hour), "2.0-1"))
	h.origin.recordErr["Debian/DSA-2"] = &advisoryfeed.Unavailable{Err: errors.New("osv.example answered 502")}

	sync, published := h.sync(t, "Debian")
	if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_PARTIAL || sync.GetSyncedAt() != nil || sync.GetFailure() == "" {
		t.Errorf("an attempt that owes a record says %v", sync)
	}
	if found := advisories(published); len(found) != 1 || found["DSA-1"] == nil {
		t.Errorf("published %v, want what could be read", found)
	}

	delete(h.origin.recordErr, "Debian/DSA-2")
	h.clock.advance(time.Minute)
	sync, published = h.sync(t, "Debian")
	if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE {
		t.Errorf("the next attempt says %v", sync)
	}
	if found := advisories(published); len(found) != 1 || found["DSA-2"] == nil {
		t.Errorf("the next attempt published %v, want only what was owed", found)
	}
}

func TestARecordThatIsNotAnAdvisoryIsRefusedAloneAndNotAskedForAgainUntilItChanges(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour), "DSA-2": started.Add(-time.Hour), "DSA-3": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))
	h.origin.serve("Debian", "DSA-2", `{"id": "DSA-2"`)
	h.origin.serve("Debian", "DSA-3", record("DSA-4", started.Add(-time.Hour), "1.0-1"))

	sync, published := h.sync(t, "Debian")
	if sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE || sync.GetRefused() != 2 || sync.GetPublished() != 1 {
		t.Errorf("the sync says %v", sync)
	}
	if found := advisories(published); len(found) != 1 || found["DSA-1"] == nil {
		t.Errorf("published %v", found)
	}
	if exposed(t, h.registry, `seagull_advisoryfeed_advisories_total{feed="Debian",outcome="refused"}`) != 2 {
		t.Error("the refusals are not counted")
	}

	h.origin.list("Debian", `"generation-2"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour), "DSA-2": started.Add(-time.Hour), "DSA-3": started.Add(-time.Hour), "DSA-9": started})
	h.sync(t, "Debian")
	if asked := h.origin.times("Debian/DSA-2"); asked != 1 {
		t.Errorf("a record refused at the same version was asked for %d times", asked)
	}

	h.origin.list("Debian", `"generation-3"`, map[string]time.Time{"DSA-2": started})
	h.origin.serve("Debian", "DSA-2", record("DSA-2", started, "2.0-1"))
	_, published = h.sync(t, "Debian")
	if found := advisories(published); found["DSA-2"] == nil {
		t.Errorf("the corrected record was not read: %v", found)
	}
}

func TestAnAdvisoryIsNeverRetractedBecauseTheFeedStoppedListingIt(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour), "DSA-2": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))
	h.origin.serve("Debian", "DSA-2", record("DSA-2", started.Add(-time.Hour), "2.0-1"))
	h.sync(t, "Debian")

	h.origin.list("Debian", `"generation-2"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	sync, published := h.sync(t, "Debian")

	if found := advisories(published); len(found) != 0 {
		t.Errorf("an advisory the feed stopped listing was published as %v", found)
	}
	if sync.GetListed() != 1 || sync.GetHeld() != 2 {
		t.Errorf("the feed lists %d and the platform holds %d, want 1 and 2", sync.GetListed(), sync.GetHeld())
	}
}

func TestARecordOlderThanTheOneHeldIsNeverTakenForIt(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-2"))
	h.sync(t, "Debian")

	h.origin.list("Debian", `"generation-2"`, map[string]time.Time{"DSA-1": started})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-3*time.Hour), "1.0-1"))
	_, published := h.sync(t, "Debian")
	if found := advisories(published); len(found) != 0 {
		t.Errorf("a record older than the one held was published: %v", found)
	}

	h.origin.list("Debian", `"generation-3"`, map[string]time.Time{"DSA-1": started})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started, "1.0-3"))
	_, published = h.sync(t, "Debian")
	if found := advisories(published); found["DSA-1"] == nil {
		t.Error("the record the index listed was not taken once the origin served it")
	}
}

func held(id string, modified time.Time, fixedIn string, normalization uint32) *vulnerabilityv1.Record {
	translated, err := osv.Translate([]byte(record(id, modified, fixedIn)))
	if err != nil {
		panic(err)
	}
	translated.Provenance.Feed = "Debian"
	translated.Provenance.FeedVersion = `"generation-0"`
	translated.Provenance.Location = "https://osv.example/Debian/" + id + ".json"
	translated.Provenance.FetchedAt = timestamppb.New(modified.Add(time.Minute))
	translated.Provenance.Digest = digest(record(id, modified, fixedIn))
	translated.Provenance.Normalization = normalization
	return &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Advisory{Advisory: translated}}
}

func TestWhatThePlatformHeldBeforeItRestartedIsNotReadAgain(t *testing.T) {
	past := history{
		held("DSA-1", started.Add(-time.Hour), "1.0-1", osv.Normalization),
		{Record: &vulnerabilityv1.Record_Sync{Sync: &vulnerabilityv1.FeedSync{
			Source: osv.Source, Feed: "Debian", Outcome: vulnerabilityv1.FeedSync_OUTCOME_COMPLETE,
			CheckedAt: timestamppb.New(started.Add(-24 * time.Hour)), SyncedAt: timestamppb.New(started.Add(-24 * time.Hour)),
		}}},
	}
	h := build(t, past)
	h.origin.indexErr["Debian"] = errors.New("osv.example answered 403")

	sync, _ := h.sync(t, "Debian")
	if !sync.GetSyncedAt().AsTime().Equal(started.Add(-24*time.Hour)) || sync.GetHeld() != 1 {
		t.Errorf("a restarted importer forgot what it held: %v", sync)
	}

	delete(h.origin.indexErr, "Debian")
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	sync, published := h.sync(t, "Debian")
	if h.origin.times("Debian/DSA-1") != 0 || len(advisories(published)) != 0 || sync.GetOutcome() != vulnerabilityv1.FeedSync_OUTCOME_COMPLETE {
		t.Errorf("an advisory held before the restart was asked for %d times and published as %v", h.origin.times("Debian/DSA-1"), advisories(published))
	}
}

// A record the log says was read in the future was not read by this importer,
// and holding it would stop the real one being asked for until then.
func TestAnAdvisoryTheImporterCouldNotHaveReadIsNotHeld(t *testing.T) {
	forged := held("DSA-1", started.Add(47*time.Hour), "9.9-9", osv.Normalization)
	forged.GetAdvisory().Provenance.FetchedAt = timestamppb.New(started.Add(48 * time.Hour))
	h := build(t, history{forged})
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))

	_, published := h.sync(t, "Debian")
	if found := advisories(published); found["DSA-1"] == nil {
		t.Errorf("a record the importer could not have read kept the real one from being asked for: %v", found)
	}
}

func TestAnAdvisoryReadWithOlderRulesIsReadAgain(t *testing.T) {
	h := build(t, history{held("DSA-1", started.Add(-time.Hour), "1.0-1", osv.Normalization-1)})
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))

	_, published := h.sync(t, "Debian")
	if found := advisories(published); found["DSA-1"].GetProvenance().GetNormalization() != osv.Normalization {
		t.Errorf("an advisory read with older rules was not read again: %v", found)
	}
}

func TestAnAdvisoryTheBackboneDidNotTakeIsOwedRatherThanForgotten(t *testing.T) {
	h := build(t, nil)
	h.origin.list("Debian", `"generation-1"`, map[string]time.Time{"DSA-1": started.Add(-time.Hour)})
	h.origin.serve("Debian", "DSA-1", record("DSA-1", started.Add(-time.Hour), "1.0-1"))
	h.backbone.refusing = 2

	if sync := h.importer.Sync(context.Background(), "Debian"); sync.GetOutcome() == vulnerabilityv1.FeedSync_OUTCOME_COMPLETE {
		t.Errorf("an attempt whose advisories the backbone refused says %v", sync)
	}
	h.backbone.taken()

	_, published := h.sync(t, "Debian")
	if found := advisories(published); found["DSA-1"] == nil {
		t.Errorf("an advisory the backbone refused was not published again: %v", found)
	}
}

func TestEveryFeedIsFollowedOnItsOwnAndOneThatFailsHoldsUpNoOther(t *testing.T) {
	h := build(t, nil, "Debian", "Alpine")
	h.origin.indexErr["Debian"] = &advisoryfeed.Unavailable{Err: errors.New("osv.example answered 503")}
	h.origin.list("Alpine", `"generation-1"`, map[string]time.Time{"ALPINE-CVE-2026-1": started.Add(-time.Hour)})
	h.origin.serve("Alpine", "ALPINE-CVE-2026-1", strings.Replace(record("ALPINE-CVE-2026-1", started.Add(-time.Hour), "8.22.0-r0"), "Debian:12", "Alpine:v3.23", 1))

	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.importer.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for h.origin.times("Alpine/ALPINE-CVE-2026-1") == 0 || h.origin.times("Debian/index") < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("the alpine record was asked for %d times and the debian index %d", h.origin.times("Alpine/ALPINE-CVE-2026-1"), h.origin.times("Debian/index"))
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("the importer stopped with %v", err)
	}

	published := advisories(h.backbone.taken())
	if published["ALPINE-CVE-2026-1"] == nil {
		t.Errorf("a failing feed held up another: %v", published)
	}
}

func TestAnImporterRefusesAFeedItCannotName(t *testing.T) {
	_, err := advisoryfeed.NewImporter(advisoryfeed.Options{
		Source: osv.Source, Feeds: []string{"Red Hat"}, Origin: newOrigin(), Translate: osv.Translate,
		Normalization: osv.Normalization, Log: &backbone{}, History: history{}, Metrics: advisoryfeed.NewMetrics(metrics.New(t.Name())),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Interval: time.Hour, RetryDelay: time.Minute, Backoff: time.Second,
		Attempts: 1, Concurrency: 1, Batch: 1, Now: time.Now,
	})
	if err == nil {
		t.Error("an importer was built for a feed whose ecosystems no asset can be placed in")
	}
}

func exposed(t *testing.T, registry *metrics.Registry, series string) float64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if value, found := strings.CutPrefix(line, series+" "); found {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				t.Fatalf("parse %s: %v", line, err)
			}
			return parsed
		}
	}
	lines := strings.Split(recorder.Body.String(), "\n")
	slices.Sort(lines)
	t.Fatalf("%s is not exposed", series)
	return 0
}
