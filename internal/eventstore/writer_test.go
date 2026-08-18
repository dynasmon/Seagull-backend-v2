package eventstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
	eventv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/event/v1"
)

type journal struct {
	mu      sync.Mutex
	entries []string
}

func (j *journal) record(entry string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, entry)
}

func (j *journal) list() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Clone(j.entries)
}

// Advances only when deliver returns nil, which is the whole of what this
// capability asks of a backbone.
type source struct {
	records   []Record
	committed bool
}

func (s *source) Consume(ctx context.Context, deliver Deliver) error {
	if err := deliver(ctx, s.records); err != nil {
		return err
	}
	s.committed = true
	return nil
}

type sink struct {
	journal   *journal
	failures  int
	attempts  int
	stored    [][]Row
	onAttempt func(attempt int)
}

func (s *sink) Store(_ context.Context, rows []Row) error {
	s.journal.record("store")
	s.attempts++
	if s.onAttempt != nil {
		s.onAttempt(s.attempts)
	}
	if s.failures > 0 {
		s.failures--
		return errors.New("the store is unavailable")
	}
	s.stored = append(s.stored, slices.Clone(rows))
	return nil
}

type quarantine struct {
	journal  *journal
	failures int
	refused  [][]Refused
}

func (q *quarantine) Publish(_ context.Context, refused []Refused) error {
	q.journal.record("quarantine")
	if q.failures > 0 {
		q.failures--
		return errors.New("the quarantine topic is unavailable")
	}
	q.refused = append(q.refused, slices.Clone(refused))
	return nil
}

func TestARecordThatIsNotAnEventIsQuarantinedAndTheBatchContinues(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{
		{Partition: 3, Offset: 17, Value: []byte("this is not a protobuf event")},
		encoded(t, populated()),
	}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared}

	if err := writerFor(t, from, to, refused).Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if len(to.stored) != 1 || len(to.stored[0]) != 1 {
		t.Fatalf("the good record did not reach the store: %+v", to.stored)
	}
	if len(refused.refused) != 1 || len(refused.refused[0]) != 1 {
		t.Fatalf("the undecodable record was not quarantined: %+v", refused.refused)
	}
	entry := refused.refused[0][0]
	if entry.Reason != ReasonUndecodable {
		t.Errorf("quarantined for %q, want %q", entry.Reason, ReasonUndecodable)
	}
	if entry.Partition != 3 || entry.Offset != 17 {
		t.Errorf("the position was lost: partition %d offset %d", entry.Partition, entry.Offset)
	}
	if !bytes.Equal(entry.Value, from.records[0].Value) {
		t.Error("a quarantined record must carry the original bytes so it stays replayable")
	}
	if !from.committed {
		t.Error("one poison record held up a partition that had nothing else wrong with it")
	}
}

func TestARecordThatBreaksTheContractIsQuarantined(t *testing.T) {
	broken := populated()
	broken.EventId = ""

	shared := &journal{}
	from := &source{records: []Record{encoded(t, broken)}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared}

	if err := writerFor(t, from, to, refused).Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if len(to.stored) != 0 {
		t.Fatalf("a record that breaks the contract was stored: %+v", to.stored)
	}
	entry := refused.refused[0][0]
	if entry.Reason != ReasonContractViolation {
		t.Errorf("quarantined for %q, want %q", entry.Reason, ReasonContractViolation)
	}
	if entry.Detail == "" {
		t.Error("a quarantined record says nothing about why it was refused")
	}
}

// The gateway's admission window does not apply to a replay, so an impossible
// instant reaches the writer intact and the driver would fold it silently.
func TestARecordTheStoreCannotHoldIsQuarantined(t *testing.T) {
	impossible := populated()
	impossible.Time.EventTime = timestamppb.New(time.Date(3000, time.January, 1, 0, 0, 0, 0, time.UTC))

	shared := &journal{}
	from := &source{records: []Record{encoded(t, impossible)}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared}

	if err := writerFor(t, from, to, refused).Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if len(to.stored) != 0 {
		t.Fatalf("an instant the store cannot hold was written anyway: %+v", to.stored)
	}
	if entry := refused.refused[0][0]; entry.Reason != ReasonUnstorable {
		t.Errorf("quarantined for %q, want %q", entry.Reason, ReasonUnstorable)
	}
}

func TestABatchIsRetriedUntilItIsDurable(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{encoded(t, populated())}}
	to := &sink{journal: shared, failures: 2}
	refused := &quarantine{journal: shared}

	if err := writerFor(t, from, to, refused).Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if to.attempts != 3 {
		t.Errorf("the batch was written on attempt %d, want the third", to.attempts)
	}
	if len(to.stored) != 1 {
		t.Errorf("a retried batch was stored %d times, want once", len(to.stored))
	}
	if !from.committed {
		t.Error("a batch that became durable did not advance the position")
	}
}

// A store outage has to look like consumer lag, not a gap: the position may not
// advance, and nothing is published to make room.
func TestThePositionDoesNotAdvanceWhileTheStoreRefusesTheBatch(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	shared := &journal{}
	from := &source{records: []Record{
		encoded(t, populated()),
		{Partition: 1, Offset: 2, Value: []byte("not an event")},
	}}
	to := &sink{
		journal:  shared,
		failures: 1_000_000,
		onAttempt: func(attempt int) {
			if attempt == 3 {
				stop()
			}
		},
	}
	refused := &quarantine{journal: shared}

	err := writerFor(t, from, to, refused).Run(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a writer stopped mid-retry returned %v, want context.Canceled", err)
	}
	if from.committed {
		t.Error("the position advanced over a batch that never became durable")
	}
	if len(refused.refused) != 0 {
		t.Error("a poison record was published while the batch it shared was not durable")
	}
}

// Storing first is what makes a retry safe: if the store fails nothing has been
// published, so the retry cannot leave a second copy on the quarantine topic.
func TestEventsAreStoredBeforeAnythingIsQuarantined(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{
		{Partition: 0, Offset: 1, Value: []byte("not an event")},
		encoded(t, populated()),
	}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared}

	if err := writerFor(t, from, to, refused).Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if got := shared.list(); !slices.Equal(got, []string{"store", "quarantine"}) {
		t.Fatalf("the batch was handled in the order %v", got)
	}
}

func TestNothingIsDroppedWhenQuarantineIsUnavailable(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{
		{Partition: 0, Offset: 1, Value: []byte("not an event")},
		encoded(t, populated()),
	}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared, failures: 1}

	if err := writerFor(t, from, to, refused).Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	want := []string{"store", "quarantine", "store", "quarantine"}
	if got := shared.list(); !slices.Equal(got, want) {
		t.Fatalf("a failed quarantine publish was handled as %v, want the whole batch retried", got)
	}
	if !from.committed {
		t.Error("the position did not advance after the retry succeeded")
	}
}

func TestAWriterRefusesToBeBuiltWithoutWhatItNeeds(t *testing.T) {
	complete := WriterOptions{
		Source:        &source{},
		Sink:          &sink{journal: &journal{}},
		Quarantine:    &quarantine{journal: &journal{}},
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 5 * time.Millisecond,
	}

	for name, break_ := range map[string]func(*WriterOptions){
		"no source":            func(o *WriterOptions) { o.Source = nil },
		"no sink":              func(o *WriterOptions) { o.Sink = nil },
		"nowhere to refuse to": func(o *WriterOptions) { o.Quarantine = nil },
		"no metrics":           func(o *WriterOptions) { o.Metrics = nil },
		"no logger":            func(o *WriterOptions) { o.Logger = nil },
		"no write budget":      func(o *WriterOptions) { o.WriteTimeout = 0 },
		"a ceiling below the floor": func(o *WriterOptions) {
			o.RetryDelay, o.MaxRetryDelay = time.Minute, time.Second
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := complete
			break_(&options)
			if _, err := NewWriter(options); err == nil {
				t.Fatal("the writer was built anyway")
			}
		})
	}
}

func writerFor(t *testing.T, from *source, to *sink, refused *quarantine) *Writer {
	t.Helper()

	built, err := NewWriter(WriterOptions{
		Source:        from,
		Sink:          to,
		Quarantine:    refused,
		Metrics:       NewMetrics(metrics.New("test")),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		WriteTimeout:  time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}
	return built
}

func encoded(t *testing.T, record *eventv1.Event) Record {
	t.Helper()

	value, err := proto.Marshal(record)
	if err != nil {
		t.Fatalf("encode the event: %v", err)
	}
	return Record{
		Partition: 2,
		Offset:    9,
		Key:       []byte(record.GetOrigin().GetAgentId()),
		Value:     value,
	}
}
