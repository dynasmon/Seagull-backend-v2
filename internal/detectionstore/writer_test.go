package detectionstore

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

	"github.com/dynasmon/Seagull-backend-v2/internal/platform/metrics"
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
	journal  *journal
	failures int
	attempts int
	stored   [][]Row
}

func (s *sink) Store(_ context.Context, rows []Row) error {
	s.journal.record("store")
	s.attempts++
	if s.failures != 0 {
		if s.failures > 0 {
			s.failures--
		}
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

func encoded(t *testing.T, made proto.Message) Record {
	t.Helper()

	payload, err := proto.Marshal(made)
	if err != nil {
		t.Fatalf("encode a detection: %v", err)
	}
	return Record{Partition: 1, Offset: 42, Value: payload}
}

func writerOn(t *testing.T, from *source, to *sink, refused *quarantine) (*Writer, *bytes.Buffer) {
	t.Helper()

	var written bytes.Buffer
	writer, err := NewWriter(WriterOptions{
		Source:        from,
		Sink:          to,
		Quarantine:    refused,
		Metrics:       NewMetrics(metrics.New(t.Name())),
		Logger:        slog.New(slog.NewJSONHandler(&written, &slog.HandlerOptions{Level: slog.LevelWarn})),
		WriteTimeout:  5 * time.Second,
		RetryDelay:    time.Millisecond,
		MaxRetryDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build the writer: %v", err)
	}
	return writer, &written
}

// One record that is not a detection must never hold a partition. It is refused
// on its own and the rest of the batch is stored.
func TestARecordThatIsNotADetectionIsQuarantinedAndTheBatchContinues(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{
		{Partition: 3, Offset: 17, Value: []byte("this is not a protobuf detection")},
		encoded(t, populated()),
	}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared}

	writer, _ := writerOn(t, from, to, refused)
	if err := writer.Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if len(to.stored) != 1 || len(to.stored[0]) != 1 {
		t.Fatalf("one storable detection produced %v", to.stored)
	}
	if len(refused.refused) != 1 || len(refused.refused[0]) != 1 {
		t.Fatalf("one unreadable record produced %v", refused.refused)
	}
	if entry := refused.refused[0][0]; entry.Reason != ReasonUndecodable || entry.Offset != 17 {
		t.Errorf("the record was refused as %q at offset %d", entry.Reason, entry.Offset)
	}
	if !from.committed {
		t.Error("the batch was not committed although everything in it was handled")
	}
}

// A detection the store cannot hold is refused for that reason and not for the
// other, because an operator answers the two differently.
func TestADetectionTheStoreCannotHoldIsQuarantined(t *testing.T) {
	made := populated()
	made.DetectionId = ""

	shared := &journal{}
	from := &source{records: []Record{encoded(t, made)}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared}

	writer, _ := writerOn(t, from, to, refused)
	if err := writer.Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if len(refused.refused) != 1 || refused.refused[0][0].Reason != ReasonUnstorable {
		t.Fatalf("the record was refused as %v", refused.refused)
	}
	if len(to.stored) != 0 {
		t.Errorf("a detection the store cannot hold was written anyway: %v", to.stored)
	}
}

// A store outage is retried, not dropped, and the position stays where it is
// until the batch is durable.
func TestABatchIsRetriedUntilItIsDurable(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{encoded(t, populated())}}
	to := &sink{journal: shared, failures: 2}
	refused := &quarantine{journal: shared}

	writer, _ := writerOn(t, from, to, refused)
	if err := writer.Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if to.attempts != 3 {
		t.Errorf("the store failed twice and was reached %d times", to.attempts)
	}
	if !from.committed {
		t.Error("the batch was not committed although it became durable")
	}
}

// The order the whole card rests on: nothing advances while the store refuses.
func TestThePositionDoesNotAdvanceWhileTheStoreRefusesTheBatch(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{encoded(t, populated())}}
	to := &sink{journal: shared, failures: -1}
	refused := &quarantine{journal: shared}

	writer, written := writerOn(t, from, to, refused)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := writer.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the writer ended with %v rather than by being stopped", err)
	}
	if from.committed {
		t.Error("the batch was committed although it never became durable")
	}
	if to.attempts < 2 {
		t.Errorf("the writer reached the store %d times and gave up", to.attempts)
	}
	if !bytes.Contains(written.Bytes(), []byte("detection_batch_not_durable")) {
		t.Error("the writer did not say that the batch was not durable")
	}
}

// Nothing is dropped to make progress: a quarantine that cannot be reached
// holds the batch exactly as an unavailable store does.
func TestNothingIsDroppedWhenQuarantineIsUnavailable(t *testing.T) {
	shared := &journal{}
	from := &source{records: []Record{
		{Partition: 0, Offset: 1, Value: []byte("not a detection")},
	}}
	to := &sink{journal: shared}
	refused := &quarantine{journal: shared, failures: 1}

	writer, _ := writerOn(t, from, to, refused)
	if err := writer.Run(context.Background()); err != nil {
		t.Fatalf("run the writer: %v", err)
	}

	if len(refused.refused) != 1 {
		t.Errorf("the refused record was lost when the quarantine was unavailable: %v", refused.refused)
	}
	if !from.committed {
		t.Error("the batch was not committed although the record eventually reached quarantine")
	}
}

// A replayed batch writes the same rows under the same names, which is what
// makes the table replace rather than accumulate.
func TestAReplayedBatchWritesTheSameRows(t *testing.T) {
	names := func() []string {
		shared := &journal{}
		from := &source{records: []Record{encoded(t, populated())}}
		to := &sink{journal: shared}
		writer, _ := writerOn(t, from, to, &quarantine{journal: shared})
		if err := writer.Run(context.Background()); err != nil {
			t.Fatalf("run the writer: %v", err)
		}

		var written []string
		for _, batch := range to.stored {
			for _, row := range batch {
				written = append(written, row.DetectionID)
			}
		}
		return written
	}

	first, replayed := names(), names()
	if len(first) == 0 {
		t.Fatal("nothing was stored to compare")
	}
	if !slices.Equal(first, replayed) {
		t.Errorf("a replayed batch stored %v where the first stored %v", replayed, first)
	}
}

func TestAWriterRefusesToBeBuiltWithoutWhatItNeeds(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	complete := func(shape func(*WriterOptions)) WriterOptions {
		options := WriterOptions{
			Source:        &source{},
			Sink:          &sink{journal: &journal{}},
			Quarantine:    &quarantine{journal: &journal{}},
			Metrics:       NewMetrics(metrics.New(t.Name())),
			Logger:        logger,
			WriteTimeout:  time.Second,
			RetryDelay:    time.Millisecond,
			MaxRetryDelay: time.Second,
		}
		shape(&options)
		return options
	}

	missing := map[string]WriterOptions{
		"no source":        complete(func(o *WriterOptions) { o.Source = nil }),
		"no sink":          complete(func(o *WriterOptions) { o.Sink = nil }),
		"no quarantine":    complete(func(o *WriterOptions) { o.Quarantine = nil }),
		"no metrics":       complete(func(o *WriterOptions) { o.Metrics = nil }),
		"no logger":        complete(func(o *WriterOptions) { o.Logger = nil }),
		"no write budget":  complete(func(o *WriterOptions) { o.WriteTimeout = 0 }),
		"no retry ceiling": complete(func(o *WriterOptions) { o.MaxRetryDelay = 0 }),
	}
	for name, options := range missing {
		t.Run(name, func(t *testing.T) {
			if _, err := NewWriter(options); err == nil {
				t.Error("the writer was built without a dependency it needs")
			}
		})
	}
}
