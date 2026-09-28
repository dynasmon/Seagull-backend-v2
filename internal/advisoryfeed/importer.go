package advisoryfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/vulnerability"
	vulnerabilityv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/vulnerability/v1"
)

type Options struct {
	Source        string
	Feeds         []string
	Origin        Origin
	Translate     Translate
	Normalization uint32
	Log           Log
	History       History
	Metrics       *Metrics
	Logger        *slog.Logger
	Interval      time.Duration
	RetryDelay    time.Duration
	Backoff       time.Duration
	Attempts      int
	Concurrency   int
	Batch         int
	Now           func() time.Time
}

// What the platform holds of one advisory: the version last published, the
// rules it was read with, and a digest of what it said, so a record whose time
// moved while its content did not is not published as another version.
type holding struct {
	feed          string
	modified      time.Time
	normalization uint32
	statement     [sha256.Size]byte
}

type follow struct {
	known    string
	listings []Listing
	settled  map[string]time.Time
	syncedAt time.Time
	synced   bool
}

type Importer struct {
	source        string
	feeds         []string
	origin        Origin
	translate     Translate
	normalization uint32
	log           Log
	history       History
	metrics       *Metrics
	logger        *slog.Logger
	interval      time.Duration
	retryDelay    time.Duration
	backoff       time.Duration
	attempts      int
	batch         int
	now           func() time.Time
	fetching      chan struct{}

	mu      sync.Mutex
	held    map[string]holding
	follows map[string]*follow
}

func NewImporter(options Options) (*Importer, error) {
	switch {
	case options.Source == "":
		return nil, errors.New("the advisory importer needs the name of the source it reads")
	case len(options.Feeds) == 0:
		return nil, errors.New("the advisory importer needs at least one feed")
	case options.Origin == nil || options.Translate == nil:
		return nil, errors.New("the advisory importer needs an origin and a translation")
	case options.Log == nil || options.History == nil:
		return nil, errors.New("the advisory importer needs the log it publishes to and reads back")
	case options.Metrics == nil || options.Logger == nil:
		return nil, errors.New("the advisory importer needs metrics and a logger")
	case options.Normalization == 0:
		return nil, errors.New("the advisory importer needs the version of the rules it translates with")
	case options.Interval <= 0 || options.RetryDelay <= 0 || options.RetryDelay > options.Interval || options.Backoff <= 0:
		return nil, errors.New("the advisory importer needs an interval, and retry delays below it")
	case options.Attempts < 1 || options.Concurrency < 1 || options.Batch < 1:
		return nil, errors.New("the advisory importer needs at least one attempt, one fetch at a time and one advisory per batch")
	case options.Now == nil:
		return nil, errors.New("the advisory importer needs a clock")
	}
	for index, feed := range options.Feeds {
		if !vulnerability.Distribution(feed) {
			return nil, fmt.Errorf("%q is not a feed of a distribution the platform can place an asset in", feed)
		}
		if slices.Contains(options.Feeds[:index], feed) {
			return nil, fmt.Errorf("%q is named twice", feed)
		}
	}

	follows := make(map[string]*follow, len(options.Feeds))
	for _, feed := range options.Feeds {
		follows[feed] = &follow{settled: map[string]time.Time{}}
	}
	return &Importer{
		source:        options.Source,
		feeds:         slices.Clone(options.Feeds),
		origin:        options.Origin,
		translate:     options.Translate,
		normalization: options.Normalization,
		log:           options.Log,
		history:       options.History,
		metrics:       options.Metrics,
		logger:        options.Logger,
		interval:      options.Interval,
		retryDelay:    options.RetryDelay,
		backoff:       options.Backoff,
		attempts:      options.Attempts,
		batch:         options.Batch,
		now:           options.Now,
		fetching:      make(chan struct{}, options.Concurrency),
		held:          map[string]holding{},
		follows:       follows,
	}, nil
}

func (i *Importer) Name() string { return "advisory-importer" }

func (i *Importer) Run(ctx context.Context) error {
	if err := i.Recall(ctx); err != nil {
		return err
	}
	var following sync.WaitGroup
	for _, feed := range i.feeds {
		following.Add(1)
		go func() {
			defer following.Done()
			i.follow(ctx, feed)
		}()
	}
	following.Wait()
	return ctx.Err()
}

// What the log already holds is read back before any feed is asked anything,
// so a restarted importer asks only for what changed and a feed that fails at
// once still reports how fresh the platform's copy of it is.
func (i *Importer) Recall(ctx context.Context) error {
	if err := i.history.Replay(ctx, i.learn); err != nil {
		return fmt.Errorf("read back the advisories the platform holds: %w", err)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	for feed, state := range i.follows {
		if state.synced {
			i.metrics.recalled(feed, state.syncedAt)
		}
	}
	return nil
}

func (i *Importer) learn(record *vulnerabilityv1.Record) {
	i.mu.Lock()
	defer i.mu.Unlock()
	switch body := record.GetRecord().(type) {
	case *vulnerabilityv1.Record_Advisory:
		advisory := body.Advisory
		if advisory.GetSource() != i.source || vulnerability.Validate(advisory) != nil {
			return
		}
		provenance := advisory.GetProvenance()
		_, followed := i.follows[provenance.GetFeed()]
		read := provenance.GetFetchedAt().AsTime()
		if followed && !read.After(i.now().Add(vulnerability.MaxClockSkew)) {
			i.keep(body.Advisory)
		}
	case *vulnerabilityv1.Record_Sync:
		sync := body.Sync
		state, followed := i.follows[sync.GetFeed()]
		if sync.GetSource() != i.source || !followed || vulnerability.ValidateSync(sync) != nil {
			return
		}
		latest := i.now().Add(vulnerability.MaxClockSkew)
		if sync.GetCheckedAt().AsTime().After(latest) ||
			(sync.GetSyncedAt() != nil && sync.GetSyncedAt().AsTime().After(latest)) ||
			(sync.GetNewestListed() != nil && sync.GetNewestListed().AsTime().After(latest)) {
			return
		}
		synced := sync.GetSyncedAt()
		if synced != nil {
			at := synced.AsTime()
			if !state.synced || at.After(state.syncedAt) {
				state.syncedAt, state.synced = at, true
			}
		}
	}
}

func (i *Importer) keep(advisory *vulnerabilityv1.Advisory) {
	fresh := holding{
		feed:          advisory.GetProvenance().GetFeed(),
		modified:      advisory.GetModified().AsTime(),
		normalization: advisory.GetProvenance().GetNormalization(),
		statement:     statement(advisory),
	}
	current, held := i.held[advisory.GetId()]
	if held && fresh.modified.Before(current.modified) {
		return
	}
	i.held[advisory.GetId()] = fresh
}

func (i *Importer) follow(ctx context.Context, feed string) {
	wait := i.retryDelay
	for {
		next := i.interval
		if report := i.Sync(ctx, feed); report.GetOutcome() == vulnerabilityv1.FeedSync_OUTCOME_COMPLETE {
			wait = i.retryDelay
		} else {
			next, wait = wait, min(wait*2, i.interval)
		}
		select {
		case <-time.After(next):
		case <-ctx.Done():
			return
		}
	}
}

func (i *Importer) Sync(ctx context.Context, feed string) *vulnerabilityv1.FeedSync {
	began := time.Now()
	checked := i.now().UTC()
	state := i.state(feed)
	report := &vulnerabilityv1.FeedSync{
		Source:    i.source,
		Feed:      feed,
		CheckedAt: timestamppb.New(checked),
		Outcome:   vulnerabilityv1.FeedSync_OUTCOME_FAILED,
	}

	index, err := i.index(ctx, feed, state.known)
	switch {
	case err != nil:
		report.Failure = failure("the index could not be read", err)
		return i.close(ctx, state, report, began)
	case !index.Unchanged && len(index.Listings) == 0 && index.Malformed > 0:
		report.Failure = failure("the index could not be read", fmt.Errorf("none of its %d lines names a record", index.Malformed))
		return i.close(ctx, state, report, began)
	case !index.Unchanged:
		state.known, state.listings = index.Version, latest(index.Listings)
		report.Refused += uint32(index.Malformed)
		i.metrics.settled(feed, "refused", index.Malformed)
	}
	report.FeedVersion = state.known
	report.Listed = uint32(len(state.listings))
	if newest, listed := newestOf(state.listings); listed {
		report.NewestListed = timestamppb.New(newest)
	}

	if err := i.read(ctx, feed, state, i.owed(state), report); err != nil {
		report.Outcome = vulnerabilityv1.FeedSync_OUTCOME_PARTIAL
		report.Failure = failure("some advisories are still owed", err)
		return i.close(ctx, state, report, began)
	}
	report.Outcome = vulnerabilityv1.FeedSync_OUTCOME_COMPLETE
	state.syncedAt, state.synced = checked, true
	return i.close(ctx, state, report, began)
}

func (i *Importer) close(ctx context.Context, state *follow, report *vulnerabilityv1.FeedSync, began time.Time) *vulnerabilityv1.FeedSync {
	if state.synced {
		report.SyncedAt = timestamppb.New(state.syncedAt)
	}
	report.Held = i.heldFrom(report.GetFeed())
	if ctx.Err() != nil {
		return report
	}

	if err := i.log.Publish(ctx, []*vulnerabilityv1.Record{{Record: &vulnerabilityv1.Record_Sync{Sync: report}}}); err != nil {
		i.logger.Error("advisory_feed_sync_not_published", slog.String("feed", report.GetFeed()), slog.String("error", err.Error()))
	}
	i.metrics.attempted(report, time.Since(began))
	i.logger.Info("advisory_feed_followed",
		slog.String("feed", report.GetFeed()),
		slog.String("outcome", outcomeName(report.GetOutcome())),
		slog.Int("listed", int(report.GetListed())),
		slog.Int("held", int(report.GetHeld())),
		slog.Int("published", int(report.GetPublished())),
		slog.Int("refused", int(report.GetRefused())),
		slog.String("failure", report.GetFailure()),
	)
	return report
}

func (i *Importer) owed(state *follow) []Listing {
	i.mu.Lock()
	defer i.mu.Unlock()
	var owed []Listing
	for _, listing := range state.listings {
		if settled, known := state.settled[listing.ID]; known && !listing.Modified.After(settled) {
			continue
		}
		current, held := i.held[listing.ID]
		if held && current.normalization >= i.normalization && !listing.Modified.After(current.modified) {
			continue
		}
		owed = append(owed, listing)
	}
	return owed
}

type settlement struct {
	listing   Listing
	advisory  *vulnerabilityv1.Advisory
	statement [sha256.Size]byte
	gone      bool
	refused   error
	owed      error
}

// Records are fetched a few at a time across every feed and settled one by one
// on this goroutine, which alone publishes and alone changes what is held. A
// record that cannot be fetched now stops the attempt; one that could be read
// and was not an advisory is refused alone and asked for again only once the
// feed changes it.
func (i *Importer) read(ctx context.Context, feed string, state *follow, owed []Listing, report *vulnerabilityv1.FeedSync) error {
	if len(owed) == 0 {
		return nil
	}
	work := make(chan Listing)
	settled := make(chan settlement)
	stopped := make(chan struct{})
	var stopping sync.Once
	stop := func() { stopping.Do(func() { close(stopped) }) }
	defer stop()

	go func() {
		defer close(work)
		for _, listing := range owed {
			select {
			case work <- listing:
			case <-stopped:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	var fetching sync.WaitGroup
	for range min(cap(i.fetching), len(owed)) {
		fetching.Add(1)
		go func() {
			defer fetching.Done()
			for listing := range work {
				settled <- i.settle(ctx, feed, state.known, listing)
			}
		}()
	}
	go func() {
		fetching.Wait()
		close(settled)
	}()

	var (
		batch      []settlement
		stranded   error
		unwritable bool
	)
	flush := func() {
		if len(batch) > 0 && !unwritable {
			if err := i.publish(ctx, state, batch, report); err != nil {
				unwritable, stranded = true, errors.Join(stranded, err)
				stop()
			}
		}
		batch = nil
	}
	counts := map[string]int{}
	for outcome := range settled {
		switch {
		case outcome.owed != nil:
			if stranded == nil {
				stranded = outcome.owed
			}
			stop()
		case outcome.gone:
			counts["gone"]++
			i.settleAt(state, outcome.listing)
		case outcome.refused != nil:
			counts["refused"]++
			report.Refused++
			i.settleAt(state, outcome.listing)
			i.logger.Warn("advisory_refused", slog.String("feed", feed), slog.String("advisory", outcome.listing.ID),
				slog.String("reason", bounded(outcome.refused.Error(), vulnerability.MaxFailureLength)))
		case !i.publishable(outcome):
			counts["unchanged"]++
			if !outcome.advisory.GetModified().AsTime().Before(outcome.listing.Modified) {
				i.settleAt(state, outcome.listing)
			}
		default:
			batch = append(batch, outcome)
			if len(batch) >= i.batch {
				flush()
			}
		}
	}
	flush()
	for outcome, count := range counts {
		i.metrics.settled(feed, outcome, count)
	}
	return stranded
}

func (i *Importer) settle(ctx context.Context, feed, version string, listing Listing) settlement {
	outcome := settlement{listing: listing}
	select {
	case i.fetching <- struct{}{}:
	case <-ctx.Done():
		outcome.owed = ctx.Err()
		return outcome
	}
	fetched, err := i.fetch(ctx, feed, listing.ID)
	<-i.fetching

	var unavailable *Unavailable
	switch {
	case errors.Is(err, ErrGone):
		outcome.gone = true
		return outcome
	case errors.As(err, &unavailable), ctx.Err() != nil:
		outcome.owed = err
		return outcome
	case err != nil:
		outcome.refused = err
		return outcome
	}

	advisory, err := i.translate(fetched.Body)
	switch {
	case err != nil:
		outcome.refused = err
		return outcome
	case advisory.GetId() != listing.ID:
		outcome.refused = fmt.Errorf("the record listed as %s names itself %q", listing.ID, bounded(advisory.GetId(), vulnerability.MaxIDLength))
		return outcome
	case advisory.GetProvenance().GetNormalization() != i.normalization:
		outcome.refused = fmt.Errorf("the record was translated with rules %d and this importer reads with %d",
			advisory.GetProvenance().GetNormalization(), i.normalization)
		return outcome
	}

	digest := sha256.Sum256(fetched.Body)
	advisory.Provenance.Feed = feed
	advisory.Provenance.FeedVersion = version
	advisory.Provenance.Location = fetched.Location
	advisory.Provenance.FetchedAt = timestamppb.New(i.now().UTC())
	advisory.Provenance.Digest = hex.EncodeToString(digest[:])
	if err := vulnerability.Validate(advisory); err != nil {
		outcome.refused = err
		return outcome
	}
	outcome.advisory = advisory
	outcome.statement = statement(advisory)
	return outcome
}

func (i *Importer) publishable(outcome settlement) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	current, held := i.held[outcome.listing.ID]
	if !held {
		return true
	}
	modified := outcome.advisory.GetModified().AsTime()
	switch {
	case modified.Before(current.modified):
		return false
	case current.normalization < i.normalization:
		return true
	default:
		return outcome.statement != current.statement
	}
}

func (i *Importer) publish(ctx context.Context, state *follow, batch []settlement, report *vulnerabilityv1.FeedSync) error {
	records := make([]*vulnerabilityv1.Record, 0, len(batch))
	for _, outcome := range batch {
		records = append(records, &vulnerabilityv1.Record{Record: &vulnerabilityv1.Record_Advisory{Advisory: outcome.advisory}})
	}
	if err := i.log.Publish(ctx, records); err != nil {
		return fmt.Errorf("the backbone did not take %d advisories: %w", len(records), err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	for _, outcome := range batch {
		i.held[outcome.listing.ID] = holding{
			feed:          report.GetFeed(),
			modified:      outcome.advisory.GetModified().AsTime(),
			normalization: outcome.advisory.GetProvenance().GetNormalization(),
			statement:     outcome.statement,
		}
		if !outcome.advisory.GetModified().AsTime().Before(outcome.listing.Modified) {
			state.settled[outcome.listing.ID] = outcome.listing.Modified
		}
	}
	report.Published += uint32(len(batch))
	i.metrics.settled(report.GetFeed(), "published", len(batch))
	return nil
}

func (i *Importer) settleAt(state *follow, listing Listing) {
	i.mu.Lock()
	defer i.mu.Unlock()
	state.settled[listing.ID] = listing.Modified
}

func (i *Importer) index(ctx context.Context, feed, known string) (Index, error) {
	return retried(ctx, i.attempts, i.backoff, func() (Index, error) { return i.origin.Index(ctx, feed, known) })
}

func (i *Importer) fetch(ctx context.Context, feed, id string) (Fetched, error) {
	return retried(ctx, i.attempts, i.backoff, func() (Fetched, error) { return i.origin.Record(ctx, feed, id) })
}

func retried[T any](ctx context.Context, attempts int, delay time.Duration, ask func() (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		answer, err := ask()
		var unavailable *Unavailable
		if err == nil || !errors.As(err, &unavailable) || attempt >= attempts {
			return answer, err
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return answer, ctx.Err()
		}
		delay *= 2
	}
}

func (i *Importer) state(feed string) *follow {
	i.mu.Lock()
	defer i.mu.Unlock()
	state, followed := i.follows[feed]
	if !followed {
		state = &follow{settled: map[string]time.Time{}}
		i.follows[feed] = state
	}
	return state
}

func (i *Importer) heldFrom(feed string) uint32 {
	i.mu.Lock()
	defer i.mu.Unlock()
	var count uint32
	for _, current := range i.held {
		if current.feed == feed {
			count++
		}
	}
	return count
}

func statement(advisory *vulnerabilityv1.Advisory) [sha256.Size]byte {
	stated := proto.Clone(advisory).(*vulnerabilityv1.Advisory)
	stated.Modified = nil
	stated.Provenance = nil
	encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(stated)
	return sha256.Sum256(encoded)
}

func latest(listings []Listing) []Listing {
	newest := make(map[string]time.Time, len(listings))
	for _, listing := range listings {
		if current, seen := newest[listing.ID]; !seen || listing.Modified.After(current) {
			newest[listing.ID] = listing.Modified
		}
	}
	kept := make([]Listing, 0, len(newest))
	for id, modified := range newest {
		kept = append(kept, Listing{ID: id, Modified: modified})
	}
	slices.SortFunc(kept, func(a, b Listing) int { return strings.Compare(a.ID, b.ID) })
	return kept
}

func newestOf(listings []Listing) (time.Time, bool) {
	var newest time.Time
	for _, listing := range listings {
		if listing.Modified.After(newest) {
			newest = listing.Modified
		}
	}
	return newest, len(listings) > 0
}

func failure(what string, err error) string {
	return bounded(what+": "+err.Error(), vulnerability.MaxFailureLength)
}

func bounded(text string, maximum int) string {
	if len(text) <= maximum {
		return text
	}
	cut := maximum
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}
