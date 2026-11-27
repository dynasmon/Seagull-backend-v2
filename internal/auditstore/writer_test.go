package auditstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/audit"
	"github.com/dynasmon/Seagull-backend-v2/internal/auditstore"
	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	auditv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/audit/v1"
	controlv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/control/v1"
)

var occurred = time.Date(2026, time.November, 26, 9, 30, 0, 0, time.UTC)

type memory struct {
	rows         []auditstore.Row
	failAppends  int
	appended     int
	beforeHeads  func(*memory)
	chainedCalls int
}

func (m *memory) Chained(_ context.Context, asked map[string][]string) (map[string]map[string]uint64, error) {
	m.chainedCalls++
	held := map[string]map[string]uint64{}
	for _, row := range m.rows {
		if !slices.Contains(asked[row.Chain], row.EventID) {
			continue
		}
		if held[row.Chain] == nil {
			held[row.Chain] = map[string]uint64{}
		}
		held[row.Chain][row.EventID] = row.Sequence
	}
	return held, nil
}

func (m *memory) Heads(_ context.Context, chains []string) (map[string]auditstore.Head, error) {
	if m.beforeHeads != nil {
		m.beforeHeads(m)
		m.beforeHeads = nil
	}
	heads := map[string]auditstore.Head{}
	for _, row := range m.rows {
		if !slices.Contains(chains, row.Chain) {
			continue
		}
		if head, found := heads[row.Chain]; found && head.Sequence >= row.Sequence {
			continue
		}
		heads[row.Chain] = auditstore.Head{Sequence: row.Sequence, Digest: row.Digest, Partition: row.LogPartition, Offset: row.LogOffset}
	}
	return heads, nil
}

func (m *memory) Append(_ context.Context, rows []auditstore.Row) error {
	if m.failAppends > 0 {
		m.failAppends--
		return errors.New("the store is unavailable")
	}
	m.appended++
	m.rows = append(m.rows, rows...)
	return nil
}

func (m *memory) chain(name string) []*auditv1.Entry {
	bySequence := map[uint64]auditstore.Row{}
	for _, row := range m.rows {
		if row.Chain == name {
			bySequence[row.Sequence] = row
		}
	}
	entries := make([]*auditv1.Entry, 0, len(bySequence))
	for sequence := uint64(1); ; sequence++ {
		row, found := bySequence[sequence]
		if !found {
			break
		}
		entries = append(entries, &auditv1.Entry{Event: row.Event, Chain: row.Chain, Sequence: row.Sequence, Previous: row.Previous, Digest: row.Digest})
	}
	return entries
}

type quarantined struct{ refused []auditstore.Refused }

func (q *quarantined) Publish(_ context.Context, refused []auditstore.Refused) error {
	q.refused = append(q.refused, refused...)
	return nil
}

func (q *quarantined) reasons() []string {
	reasons := make([]string, 0, len(q.refused))
	for _, entry := range q.refused {
		reasons = append(reasons, entry.Reason)
	}
	return reasons
}

type delivered struct{ batches [][]auditstore.Record }

func (d delivered) Consume(ctx context.Context, deliver auditstore.Deliver) error {
	for _, batch := range d.batches {
		if err := deliver(ctx, batch); err != nil {
			return err
		}
	}
	return nil
}

func writer(t *testing.T, source auditstore.Source, store auditstore.Store, quarantine auditstore.Quarantine, registry *metrics.Registry) *auditstore.Writer {
	t.Helper()
	built, err := auditstore.NewWriter(auditstore.WriterOptions{
		Source:        source,
		Store:         store,
		Quarantine:    quarantine,
		Metrics:       auditstore.NewMetrics(registry),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}
	return built
}

func run(t *testing.T, store auditstore.Store, quarantine *quarantined, batches ...[]auditstore.Record) *metrics.Registry {
	t.Helper()
	registry := metrics.New("test")
	if err := writer(t, delivered{batches: batches}, store, quarantine, registry).Run(context.Background()); err != nil {
		t.Fatalf("the writer stopped with %v", err)
	}
	return registry
}

func recorded(id, tenant string) *auditv1.Event {
	return &auditv1.Event{
		SchemaVersion: audit.SchemaVersion,
		EventId:       id,
		TenantId:      tenant,
		OccurredAt:    timestamppb.New(occurred),
		Actor:         &auditv1.Event_Actor{Kind: auditv1.Event_Actor_KIND_OPERATOR, Subject: "alice"},
		Action:        auditv1.Event_ACTION_ALERT_MOVED,
		Target:        &auditv1.Event_Target{Resource: controlv1.Resource_RESOURCE_ALERTS, Id: "alert-" + id},
		Outcome:       auditv1.Event_OUTCOME_SUCCEEDED,
		Origin:        &auditv1.Event_Origin{Component: "control-api"},
		Change:        &auditv1.Event_Change{Before: "open", After: "acknowledged"},
	}
}

func at(t *testing.T, partition int32, offset int64, event *auditv1.Event) auditstore.Record {
	t.Helper()
	encoded, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("encode an audit event: %v", err)
	}
	return auditstore.Record{Partition: partition, Offset: offset, Key: []byte(event.GetTenantId()), Value: encoded}
}

func verified(t *testing.T, store *memory, chain string, length uint64) []*auditv1.Entry {
	t.Helper()
	entries := store.chain(chain)
	end, err := audit.Chain{Name: chain}.Verify(entries)
	if err != nil {
		t.Fatalf("chain %q does not verify: %v", chain, err)
	}
	if end.Sequence != length {
		t.Fatalf("chain %q reaches %d, want %d", chain, end.Sequence, length)
	}
	return entries
}

func eventIDs(entries []*auditv1.Entry) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		var decoded auditv1.Event
		if err := proto.Unmarshal(entry.GetEvent(), &decoded); err != nil {
			panic(err)
		}
		ids = append(ids, decoded.GetEventId())
	}
	return ids
}

func TestEachTenantIsAChainInTheOrderTheTopicHoldsIt(t *testing.T) {
	store, refused := &memory{}, &quarantined{}
	run(t, store, refused,
		[]auditstore.Record{
			at(t, 0, 10, recorded("a1", "tenant-a")),
			at(t, 1, 3, recorded("b1", "tenant-b")),
			at(t, 0, 11, recorded("01", "")),
			at(t, 0, 12, recorded("a2", "tenant-a")),
		},
		[]auditstore.Record{at(t, 0, 13, recorded("a3", "tenant-a"))},
	)

	if ids := eventIDs(verified(t, store, "tenant-a", 3)); !slices.Equal(ids, []string{"a1", "a2", "a3"}) {
		t.Errorf("tenant-a's chain holds %v", ids)
	}
	verified(t, store, "tenant-b", 1)
	verified(t, store, "", 1)
	if len(refused.refused) != 0 {
		t.Errorf("events the contract describes were quarantined: %v", refused.reasons())
	}

	first := store.chain("tenant-a")[0]
	for _, row := range store.rows {
		if row.Chain != "tenant-a" || row.Sequence != 1 {
			continue
		}
		if !bytes.Equal(row.Event, first.GetEvent()) || row.EventID != "a1" || row.Action != "alert_moved" || row.ActorSubject != "alice" ||
			row.TargetID != "alert-a1" || !row.OccurredAt.Equal(occurred) || row.LogPartition != 0 || row.LogOffset != 10 {
			t.Errorf("the first entry is stored as %+v", row)
		}
	}
}

func TestARedeliveredBatchIsFoundChainedAndNotChainedAgain(t *testing.T) {
	store, refused := &memory{}, &quarantined{}
	batch := []auditstore.Record{at(t, 0, 0, recorded("a1", "tenant-a")), at(t, 0, 1, recorded("a2", "tenant-a"))}
	registry := run(t, store, refused, batch, batch, append(batch, at(t, 0, 2, recorded("a3", "tenant-a"))))

	if ids := eventIDs(verified(t, store, "tenant-a", 3)); !slices.Equal(ids, []string{"a1", "a2", "a3"}) {
		t.Errorf("a batch delivered three times left %v", ids)
	}
	if got := counted(t, registry, `seagull_auditstore_events_total{outcome="replayed"}`); got != 4 {
		t.Errorf("%v records were counted as replayed, want 4", got)
	}
}

func TestAnEventPublishedTwiceIsChainedOnce(t *testing.T) {
	store, refused := &memory{}, &quarantined{}
	registry := run(t, store, refused,
		[]auditstore.Record{at(t, 0, 0, recorded("a1", "tenant-a")), at(t, 0, 1, recorded("a1", "tenant-a")), at(t, 0, 2, recorded("a2", "tenant-a"))},
		[]auditstore.Record{at(t, 0, 7, recorded("a1", "tenant-a")), at(t, 0, 8, recorded("a3", "tenant-a"))},
	)

	if ids := eventIDs(verified(t, store, "tenant-a", 3)); !slices.Equal(ids, []string{"a1", "a2", "a3"}) {
		t.Errorf("an event an outbox published again left %v", ids)
	}
	if got := counted(t, registry, `seagull_auditstore_events_total{outcome="duplicate"}`); got != 2 {
		t.Errorf("%v records were counted as duplicates, want 2", got)
	}
}

func TestARecordTheContractRefusesIsQuarantinedAndTheChainGoesOn(t *testing.T) {
	store, refused := &memory{}, &quarantined{}
	invalid := recorded("a2", "tenant-a")
	invalid.Actor = nil
	misKeyed := at(t, 0, 3, recorded("a3", "tenant-a"))
	misKeyed.Key = []byte("tenant-b")
	registry := run(t, store, refused, []auditstore.Record{
		at(t, 0, 0, recorded("a1", "tenant-a")),
		{Partition: 0, Offset: 1, Key: []byte("tenant-a"), Value: []byte{0xff, 0xff}},
		at(t, 0, 2, invalid),
		misKeyed,
		at(t, 0, 4, recorded("a4", "tenant-a")),
	})

	if ids := eventIDs(verified(t, store, "tenant-a", 2)); !slices.Equal(ids, []string{"a1", "a4"}) {
		t.Errorf("the chain holds %v", ids)
	}
	want := []string{auditstore.ReasonUndecodable, auditstore.ReasonContractViolation, auditstore.ReasonMisplaced}
	if got := refused.reasons(); !slices.Equal(got, want) {
		t.Fatalf("the quarantine holds %v, want %v", got, want)
	}
	if refused.refused[2].Offset != 3 || !bytes.Equal(refused.refused[2].Value, misKeyed.Value) {
		t.Errorf("the mis-keyed record was quarantined as %+v", refused.refused[2])
	}
	if got := counted(t, registry, `seagull_auditstore_refusals_total{reason="contract_violation"}`); got != 1 {
		t.Errorf("%v contract violations were counted", got)
	}
}

func TestAChainIsNeverExtendedFromAPartitionItIsNotReadFrom(t *testing.T) {
	store, refused := &memory{}, &quarantined{}
	run(t, store, refused,
		[]auditstore.Record{at(t, 0, 0, recorded("a1", "tenant-a"))},
		[]auditstore.Record{at(t, 2, 0, recorded("a2", "tenant-a")), at(t, 0, 1, recorded("a3", "tenant-a"))},
	)

	if ids := eventIDs(verified(t, store, "tenant-a", 2)); !slices.Equal(ids, []string{"a1", "a3"}) {
		t.Errorf("the chain holds %v", ids)
	}
	if got := refused.reasons(); !slices.Equal(got, []string{auditstore.ReasonMisplaced}) || refused.refused[0].Partition != 2 {
		t.Errorf("the quarantine holds %+v", refused.refused)
	}
}

func TestAStoreOutageCostsTimeAndNeverAnEntry(t *testing.T) {
	store, refused := &memory{failAppends: 3}, &quarantined{}
	registry := run(t, store, refused, []auditstore.Record{at(t, 0, 0, recorded("a1", "tenant-a")), at(t, 0, 1, recorded("a2", "tenant-a"))})

	verified(t, store, "tenant-a", 2)
	if got := counted(t, registry, `seagull_auditstore_batches_total{outcome="retried"}`); got != 3 {
		t.Errorf("%v retries were counted, want 3", got)
	}
}

// What a crash leaves: the batch reached the store, the position did not move,
// and the batch arrives again with the records that followed it.
func TestAWriterThatRecoveredChainsWhatOneThatNeverStoppedDid(t *testing.T) {
	var records []auditstore.Record
	for index := range 12 {
		tenant := []string{"tenant-a", "tenant-b", ""}[index%3]
		records = append(records, at(t, 0, int64(index), recorded(fmt.Sprintf("%02x", index), tenant)))
	}
	records = append(records, at(t, 0, 12, recorded("00", "tenant-a")))

	steady := &memory{}
	run(t, steady, &quarantined{}, records[:5], records[5:9], records[9:])

	recovered := &memory{}
	run(t, recovered, &quarantined{}, records[:5], records[3:9])
	run(t, recovered, &quarantined{}, records[6:], records[2:])

	for _, chain := range []string{"tenant-a", "tenant-b", ""} {
		if !equalEntries(steady.chain(chain), recovered.chain(chain)) {
			t.Errorf("chain %q differs between a writer that never stopped and one that recovered", chain)
		}
	}
	verified(t, recovered, "tenant-a", 4)
}

// A writer that lost its partition and has not noticed decides the records it
// fetched from the store as it stood, and its insert may land after the writer
// that took the partition over wrote the same records: the rows are the same.
func TestTwoWritersOnOnePartitionMakeTheSameEntries(t *testing.T) {
	var records []auditstore.Record
	for index := range 6 {
		records = append(records, at(t, 1, int64(index), recorded(fmt.Sprintf("%02x", index), "tenant-a")))
	}

	shared := &memory{}
	run(t, shared, &quarantined{}, records[:2])

	late := &heldBack{memory: shared}
	run(t, late, &quarantined{}, records[2:5])
	run(t, shared, &quarantined{}, records[2:])
	shared.rows = append(shared.rows, late.pending...)

	if len(late.pending) != 3 {
		t.Fatalf("the writer that lost its partition decided %d entries, want 3", len(late.pending))
	}
	written := map[uint64][]byte{}
	for _, row := range shared.rows {
		if held, found := written[row.Sequence]; found && !bytes.Equal(held, row.Digest) {
			t.Fatalf("two different entries were written at sequence %d", row.Sequence)
		}
		written[row.Sequence] = row.Digest
	}
	verified(t, shared, "tenant-a", 6)
}

type heldBack struct {
	*memory
	pending []auditstore.Row
}

func (h *heldBack) Append(_ context.Context, rows []auditstore.Row) error {
	h.pending = append(h.pending, rows...)
	return nil
}

// Another writer's entry may land between the two reads: it is then a head the
// batch's records are found behind.
func TestAnEntryThatLandsBetweenTheTwoReadsIsFoundChained(t *testing.T) {
	other := &memory{}
	run(t, other, &quarantined{}, []auditstore.Record{at(t, 0, 0, recorded("a1", "tenant-a")), at(t, 0, 1, recorded("a2", "tenant-a"))})

	store := &memory{rows: slices.Clone(other.rows[:1])}
	store.beforeHeads = func(m *memory) { m.rows = append(m.rows, other.rows[1]) }
	registry := run(t, store, &quarantined{}, []auditstore.Record{at(t, 0, 1, recorded("a2", "tenant-a")), at(t, 0, 2, recorded("a3", "tenant-a"))})

	if ids := eventIDs(verified(t, store, "tenant-a", 3)); !slices.Equal(ids, []string{"a1", "a2", "a3"}) {
		t.Errorf("the chain holds %v", ids)
	}
	if got := counted(t, registry, `seagull_auditstore_batches_total{outcome="unordered"}`); got != 0 {
		t.Errorf("a store that read its writes in order was taken as unordered %v times", got)
	}
}

func TestAnEventHeldBeyondTheHeadTheStoreAnsweredIsNotDecidedOn(t *testing.T) {
	chained := &memory{}
	run(t, chained, &quarantined{}, []auditstore.Record{at(t, 0, 0, recorded("a1", "tenant-a")), at(t, 0, 1, recorded("a2", "tenant-a"))})
	lagging := &laggingHeads{memory: chained}

	registry := metrics.New("test")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		batch := []auditstore.Record{at(t, 0, 1, recorded("a2", "tenant-a")), at(t, 0, 2, recorded("a3", "tenant-a"))}
		stopped <- writer(t, delivered{batches: [][]auditstore.Record{batch}}, lagging, &quarantined{}, registry).Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for counted(t, registry, `seagull_auditstore_batches_total{outcome="unordered"}`) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-stopped; !errors.Is(err, context.Canceled) {
		t.Fatalf("the writer stopped with %v", err)
	}
	if got := counted(t, registry, `seagull_auditstore_batches_total{outcome="unordered"}`); got < 2 {
		t.Fatalf("an event held beyond the head the store answered was decided on: %v unordered batches", got)
	}
	if chained.appended != 1 {
		t.Errorf("a batch read out of order appended entries")
	}
}

// A head read from a replica behind the one that answered which events are held.
type laggingHeads struct{ *memory }

func (l *laggingHeads) Heads(ctx context.Context, chains []string) (map[string]auditstore.Head, error) {
	behind := &memory{rows: l.rows[:1]}
	return behind.Heads(ctx, chains)
}

func equalEntries(a, b []*auditv1.Entry) bool {
	return slices.EqualFunc(a, b, func(x, y *auditv1.Entry) bool { return proto.Equal(x, y) })
}

func counted(t *testing.T, registry *metrics.Registry, series string) float64 {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		value, found := strings.CutPrefix(line, series+" ")
		if !found {
			continue
		}
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Fatalf("parse %s: %v", line, err)
		}
		return parsed
	}
	return 0
}
